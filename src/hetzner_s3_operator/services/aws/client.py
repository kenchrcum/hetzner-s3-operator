"""AWS S3 client implementation."""

from __future__ import annotations

import logging
from typing import Any

import boto3
from botocore.exceptions import ClientError

from ..s3.base import S3Provider
from .models import BucketConfig

logger = logging.getLogger(__name__)


class AWSProvider:
    """AWS S3 provider implementation."""

    def __init__(
        self,
        endpoint: str,
        region: str,
        access_key: str,
        secret_key: str,
        session_token: str | None = None,
        path_style: bool = True,
        insecure_skip_verify: bool = False,
        iam_endpoint: str | None = None,
        iam_region: str | None = None,
    ) -> None:
        """Initialize AWS S3 provider.

        Args:
            endpoint: S3 endpoint URL
            region: AWS region
            access_key: Access key ID
            secret_key: Secret access key
            session_token: Optional session token for temporary credentials
            path_style: Use path-style addressing
            insecure_skip_verify: Skip TLS verification
            iam_endpoint: Optional IAM endpoint URL for user management
            iam_region: Optional IAM region (defaults to us-east-1)
        """
        self.endpoint = endpoint
        self.region = region
        self.path_style = path_style
        self.iam_endpoint = iam_endpoint
        self.iam_region = iam_region or "us-east-1"

        # Configure boto3 client
        config = boto3.session.Config(
            signature_version="s3v4",
            s3={"addressing_style": "path" if path_style else "auto"},
        )

        # Configure SSL if needed
        if insecure_skip_verify:
            import ssl

            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        self.client = boto3.client(
            "s3",
            endpoint_url=endpoint,
            region_name=region,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token,
            config=config,
            verify=not insecure_skip_verify,
        )
        
        # Initialize IAM client if endpoint is provided
        self.iam_client = None
        if iam_endpoint:
            self.iam_client = boto3.client(
                "iam",
                endpoint_url=iam_endpoint,
                region_name=self.iam_region,
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                aws_session_token=session_token,
                config=config,
                verify=not insecure_skip_verify,
            )

    def list_buckets(self) -> list[str]:
        """List all buckets."""
        try:
            response = self.client.list_buckets()
            return [bucket["Name"] for bucket in response.get("Buckets", [])]
        except ClientError as e:
            logger.error(f"Failed to list buckets: {e}")
            raise

    def create_bucket(self, name: str, config: dict[str, Any]) -> None:
        """Create a bucket with configuration."""
        try:
            # Create bucket
            create_params = {"Bucket": name}
            region = config.get("region")
            if region:
                create_params["CreateBucketConfiguration"] = {"LocationConstraint": region}

            self.client.create_bucket(**create_params)

            # Configure versioning
            if config.get("versioning_enabled"):
                self.set_bucket_versioning(name, True, config.get("mfa_delete", False))

            # Configure encryption
            if config.get("encryption_enabled"):
                algorithm = config.get("encryption_algorithm", "AES256")
                kms_key_id = config.get("kms_key_id")
                try:
                    self.set_bucket_encryption(name, algorithm, kms_key_id)
                except ClientError as enc_error:
                    # Log warning but don't fail bucket creation
                    # Some regions/providers may not support encryption
                    logger.warning(f"Failed to set encryption for bucket {name}: {enc_error}. Bucket created without encryption.")

            # Set tags
            tags = config.get("tags")
            if tags:
                self.set_bucket_tags(name, tags)

            # Configure lifecycle rules
            lifecycle_rules = config.get("lifecycle_rules", [])
            if lifecycle_rules:
                try:
                    self.set_bucket_lifecycle(name, lifecycle_rules)
                except ClientError as lifecycle_error:
                    # Log warning but don't fail bucket creation
                    logger.warning(f"Failed to set lifecycle for bucket {name}: {lifecycle_error}. Bucket created without lifecycle configuration.")

            # Configure CORS
            cors_rules = config.get("cors_rules", [])
            if cors_rules:
                try:
                    self.set_bucket_cors(name, cors_rules)
                except ClientError as cors_error:
                    # Log warning but don't fail bucket creation
                    logger.warning(f"Failed to set CORS for bucket {name}: {cors_error}. Bucket created without CORS configuration.")

        except ClientError as e:
            # Don't log BucketAlreadyExists as an error - it's expected if bucket already exists
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code != "BucketAlreadyExists":
                logger.error(f"Failed to create bucket {name}: {e}")
            raise

    def is_bucket_empty(self, name: str) -> bool:
        """Check if a bucket is empty.
        
        Args:
            name: Bucket name
            
        Returns:
            True if bucket is empty, False otherwise
        """
        try:
            # Use list_objects_v2 to check if bucket has any objects
            response = self.client.list_objects_v2(Bucket=name, MaxKeys=1)
            # If there are any contents, the bucket is not empty
            return not response.get("Contents", [])
        except ClientError as e:
            logger.error(f"Failed to check if bucket {name} is empty: {e}")
            raise
    
    def empty_bucket(self, name: str) -> None:
        """Empty a bucket by deleting all objects and versions.
        
        Args:
            name: Bucket name
        """
        try:
            logger.info(f"Emptying bucket {name}")
            
            # Check if versioning is enabled
            versioning = self.get_bucket_versioning(name)
            is_versioned = versioning.get("enabled", False)
            
            if is_versioned:
                # Delete all object versions
                logger.info(f"Bucket {name} has versioning enabled, deleting all versions")
                paginator = self.client.get_paginator("list_object_versions")
                
                for page in paginator.paginate(Bucket=name):
                    # Delete marker versions
                    for delete_marker in page.get("DeleteMarkers", []):
                        try:
                            self.client.delete_object(
                                Bucket=name,
                                Key=delete_marker["Key"],
                                VersionId=delete_marker["VersionId"]
                            )
                            logger.debug(f"Deleted delete marker: {delete_marker['Key']} (VersionId: {delete_marker['VersionId']})")
                        except ClientError as e:
                            logger.warning(f"Failed to delete delete marker {delete_marker['Key']}: {e}")
                    
                    # Delete object versions
                    for obj in page.get("Versions", []):
                        try:
                            self.client.delete_object(
                                Bucket=name,
                                Key=obj["Key"],
                                VersionId=obj["VersionId"]
                            )
                            logger.debug(f"Deleted object version: {obj['Key']} (VersionId: {obj['VersionId']})")
                        except ClientError as e:
                            logger.warning(f"Failed to delete object version {obj['Key']}: {e}")
            else:
                # Delete all objects
                logger.info(f"Bucket {name} does not have versioning, deleting all objects")
                paginator = self.client.get_paginator("list_objects_v2")
                
                for page in paginator.paginate(Bucket=name):
                    for obj in page.get("Contents", []):
                        try:
                            self.client.delete_object(Bucket=name, Key=obj["Key"])
                            logger.debug(f"Deleted object: {obj['Key']}")
                        except ClientError as e:
                            logger.warning(f"Failed to delete object {obj['Key']}: {e}")
            
            logger.info(f"Successfully emptied bucket {name}")
        except ClientError as e:
            logger.error(f"Failed to empty bucket {name}: {e}")
            raise
    
    def delete_bucket(self, name: str, force: bool = False) -> None:
        """Delete a bucket.
        
        Args:
            name: Bucket name
            force: If True, empty the bucket before deletion if it's not empty
        """
        try:
            # Check if bucket is empty
            if not self.is_bucket_empty(name):
                if force:
                    logger.info(f"Bucket {name} is not empty, emptying it before deletion")
                    self.empty_bucket(name)
                else:
                    raise ValueError(f"Bucket {name} is not empty. Set force=True to empty it before deletion.")
            
            # Delete the bucket
            self.client.delete_bucket(Bucket=name)
            logger.info(f"Successfully deleted bucket {name}")
        except ClientError as e:
            logger.error(f"Failed to delete bucket {name}: {e}")
            raise

    def bucket_exists(self, name: str) -> bool:
        """Check if bucket exists."""
        try:
            self.client.head_bucket(Bucket=name)
            return True
        except ClientError:
            return False

    def get_bucket_versioning(self, name: str) -> dict[str, bool]:
        """Get bucket versioning configuration."""
        try:
            response = self.client.get_bucket_versioning(Bucket=name)
            return {
                "enabled": response.get("Status") == "Enabled",
                "mfa_delete": response.get("MFADelete") == "Enabled",
            }
        except ClientError as e:
            logger.error(f"Failed to get versioning for bucket {name}: {e}")
            raise

    def set_bucket_versioning(self, name: str, enabled: bool, mfa_delete: bool = False) -> None:
        """Set bucket versioning configuration."""
        try:
            versioning_config = {
                "Status": "Enabled" if enabled else "Suspended",
            }
            if mfa_delete:
                versioning_config["MFADelete"] = "Enabled"
            else:
                versioning_config["MFADelete"] = "Disabled"

            self.client.put_bucket_versioning(
                Bucket=name,
                VersioningConfiguration=versioning_config,
            )
        except ClientError as e:
            logger.error(f"Failed to set versioning for bucket {name}: {e}")
            raise

    def get_bucket_encryption(self, name: str) -> dict[str, str | None]:
        """Get bucket encryption configuration."""
        try:
            response = self.client.get_bucket_encryption(Bucket=name)
            rules = response.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            if rules:
                sse_config = rules[0].get("ApplyServerSideEncryptionByDefault", {})
                return {
                    "algorithm": sse_config.get("SSEAlgorithm"),
                    "kms_key_id": sse_config.get("KMSMasterKeyID"),
                }
            return {"algorithm": None, "kms_key_id": None}
        except ClientError as e:
            # Encryption not configured
            if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                return {"algorithm": None, "kms_key_id": None}
            logger.error(f"Failed to get encryption for bucket {name}: {e}")
            raise

    def set_bucket_encryption(self, name: str, algorithm: str, kms_key_id: str | None = None) -> None:
        """Set bucket encryption configuration."""
        try:
            encryption_config = {
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": algorithm,
                        }
                    }
                ]
            }

            if kms_key_id:
                encryption_config["Rules"][0]["ApplyServerSideEncryptionByDefault"]["KMSMasterKeyID"] = (
                    kms_key_id
                )

            self.client.put_bucket_encryption(
                Bucket=name,
                ServerSideEncryptionConfiguration=encryption_config,
            )
        except ClientError as e:
            logger.error(f"Failed to set encryption for bucket {name}: {e}")
            raise

    def set_bucket_policy(self, name: str, policy: dict[str, Any]) -> None:
        """Set bucket policy."""
        logger.info(f"Starting bucket policy creation for bucket {name}")
        try:
            import json

            logger.info(f"Original policy for bucket {name}: {policy}")
            # Convert CRD policy format to AWS format
            aws_policy = self._convert_policy_to_aws_format(policy)
            logger.info(f"Converted policy for bucket {name}: {aws_policy}")

            policy_json = json.dumps(aws_policy)
            logger.info(f"Policy JSON for bucket {name}: {policy_json}")

            logger.info(f"Calling put_bucket_policy for bucket {name}")
            response = self.client.put_bucket_policy(
                Bucket=name,
                Policy=policy_json,
            )
            logger.info(f"put_bucket_policy response: {response}")
            logger.info(f"Successfully set bucket policy for {name}")

        except ClientError as e:
            logger.error(f"Failed to set policy for bucket {name}: {e}")
            logger.error(f"Policy that failed: {json.dumps(aws_policy) if 'aws_policy' in locals() else 'N/A'}")
            logger.error(f"Bucket policy error details: {e.response}")
            raise
    
    def _convert_policy_to_aws_format(self, policy: dict[str, Any]) -> dict[str, Any]:
        """Convert CRD policy format to AWS IAM policy format.
        
        CRD uses lowercase keys (statement, effect, principal, action, resource)
        AWS expects PascalCase keys (Statement, Effect, Principal, Action, Resource)
        """
        aws_policy = {}
        
        # Copy version
        if "version" in policy:
            aws_policy["Version"] = policy["version"]
        
        # Convert statements
        if "statement" in policy:
            aws_statements = []
            for stmt in policy["statement"]:
                aws_stmt = {}
                
                # Copy optional fields
                if "sid" in stmt:
                    aws_stmt["Sid"] = stmt["sid"]
                
                # Required fields with capitalization
                if "effect" in stmt:
                    aws_stmt["Effect"] = stmt["effect"]
                if "principal" in stmt:
                    principal = stmt["principal"]
                    # Convert principal to proper format
                    # If it's a string starting with "arn:", wrap it in {"AWS": principal}
                    if isinstance(principal, str) and principal.startswith("arn:"):
                        aws_stmt["Principal"] = {"AWS": principal}
                    else:
                        aws_stmt["Principal"] = principal
                if "notPrincipal" in stmt:
                    not_principal = stmt["notPrincipal"]
                    # Convert notPrincipal to proper format
                    # If it's a string (ARN), wrap it in {"AWS": not_principal}
                    # If it's already a dict, use as-is
                    if isinstance(not_principal, str):
                        aws_stmt["NotPrincipal"] = {"AWS": not_principal}
                    else:
                        aws_stmt["NotPrincipal"] = not_principal
                if "action" in stmt:
                    aws_stmt["Action"] = stmt["action"]
                if "resource" in stmt:
                    aws_stmt["Resource"] = stmt["resource"]
                if "condition" in stmt:
                    aws_stmt["Condition"] = stmt["condition"]
                
                aws_statements.append(aws_stmt)
            
            aws_policy["Statement"] = aws_statements
        
        logger.debug(f"Converted policy from CRD format to AWS format: {aws_policy}")
        return aws_policy

    def get_bucket_policy(self, name: str) -> dict[str, Any] | None:
        """Get bucket policy.
        
        Returns:
            Policy document dict if policy exists, None if no policy is set
        """
        try:
            response = self.client.get_bucket_policy(Bucket=name)
            import json

            return json.loads(response["Policy"])
        except ClientError as e:
            # No policy configured - return None
            if e.response.get("Error", {}).get("Code") == "NoSuchBucketPolicy":
                return None
            logger.error(f"Failed to get policy for bucket {name}: {e}")
            raise

    def delete_bucket_policy(self, name: str) -> None:
        """Delete bucket policy."""
        try:
            self.client.delete_bucket_policy(Bucket=name)
        except ClientError as e:
            logger.error(f"Failed to delete policy for bucket {name}: {e}")
            raise

    def get_bucket_tags(self, name: str) -> dict[str, str]:
        """Get bucket tags."""
        try:
            response = self.client.get_bucket_tagging(Bucket=name)
            tags = {}
            for tag in response.get("TagSet", []):
                tags[tag["Key"]] = tag["Value"]
            return tags
        except ClientError as e:
            # Tags not configured - return empty dict
            if e.response["Error"]["Code"] == "NoSuchTagSet":
                return {}
            logger.error(f"Failed to get tags for bucket {name}: {e}")
            raise

    def set_bucket_tags(self, name: str, tags: dict[str, str]) -> None:
        """Set bucket tags."""
        try:
            tag_set = [{"Key": k, "Value": v} for k, v in tags.items()]
            self.client.put_bucket_tagging(
                Bucket=name,
                Tagging={"TagSet": tag_set},
            )
        except ClientError as e:
            logger.error(f"Failed to set tags for bucket {name}: {e}")
            raise

    def get_bucket_lifecycle(self, name: str) -> dict[str, Any] | None:
        """Get bucket lifecycle configuration.
        
        Returns:
            Lifecycle configuration dict if exists, None otherwise
        """
        try:
            response = self.client.get_bucket_lifecycle_configuration(Bucket=name)
            return response
        except ClientError as e:
            # No lifecycle configuration - return None
            if e.response.get("Error", {}).get("Code") == "NoSuchLifecycleConfiguration":
                return None
            logger.error(f"Failed to get lifecycle configuration for bucket {name}: {e}")
            raise

    def set_bucket_lifecycle(self, name: str, rules: list[dict[str, Any]]) -> None:
        """Set bucket lifecycle configuration.
        
        Args:
            name: Bucket name
            rules: List of lifecycle rules in CRD format
        """
        try:
            # Convert CRD format to AWS format
            lifecycle_config = {"Rules": []}
            
            for rule in rules:
                aws_rule: dict[str, Any] = {
                    "ID": rule.get("id"),
                    "Status": rule.get("status", "Enabled"),
                }
                
                # Add prefix filter if specified
                if "prefix" in rule:
                    aws_rule["Filter"] = {"Prefix": rule["prefix"]}
                
                # Add expiration if specified
                expiration = rule.get("expiration")
                if expiration:
                    if "days" in expiration:
                        aws_rule["Expiration"] = {"Days": expiration["days"]}
                    elif "date" in expiration:
                        aws_rule["Expiration"] = {"Date": expiration["date"]}
                
                # Add transitions if specified
                transitions = rule.get("transitions", [])
                if transitions:
                    aws_rule["Transitions"] = []
                    for transition in transitions:
                        aws_transition: dict[str, Any] = {
                            "Days": transition["days"],
                            "StorageClass": transition["storageClass"],
                        }
                        aws_rule["Transitions"].append(aws_transition)
                
                lifecycle_config["Rules"].append(aws_rule)
            
            self.client.put_bucket_lifecycle_configuration(
                Bucket=name,
                LifecycleConfiguration=lifecycle_config,
            )
            logger.info(f"Set lifecycle configuration for bucket {name}")
        except ClientError as e:
            logger.error(f"Failed to set lifecycle configuration for bucket {name}: {e}")
            raise

    def delete_bucket_lifecycle(self, name: str) -> None:
        """Delete bucket lifecycle configuration."""
        try:
            self.client.delete_bucket_lifecycle(Bucket=name)
            logger.info(f"Deleted lifecycle configuration for bucket {name}")
        except ClientError as e:
            # Ignore if lifecycle doesn't exist
            if e.response.get("Error", {}).get("Code") == "NoSuchLifecycleConfiguration":
                logger.debug(f"No lifecycle configuration to delete for bucket {name}")
                return
            logger.error(f"Failed to delete lifecycle configuration for bucket {name}: {e}")
            raise

    def get_bucket_cors(self, name: str) -> dict[str, Any] | None:
        """Get bucket CORS configuration.
        
        Returns:
            CORS configuration dict if exists, None otherwise
        """
        try:
            response = self.client.get_bucket_cors(Bucket=name)
            return response
        except ClientError as e:
            # No CORS configuration - return None
            if e.response.get("Error", {}).get("Code") == "NoSuchCORSConfiguration":
                return None
            logger.error(f"Failed to get CORS configuration for bucket {name}: {e}")
            raise

    def set_bucket_cors(self, name: str, rules: list[dict[str, Any]]) -> None:
        """Set bucket CORS configuration.
        
        Args:
            name: Bucket name
            rules: List of CORS rules in CRD format
        """
        try:
            # Convert CRD format to AWS format
            cors_config = {"CORSRules": []}
            
            for rule in rules:
                aws_rule: dict[str, Any] = {
                    "AllowedOrigins": rule.get("allowedOrigins", []),
                    "AllowedMethods": rule.get("allowedMethods", []),
                }
                
                # Add optional fields
                if "allowedHeaders" in rule:
                    aws_rule["AllowedHeaders"] = rule["allowedHeaders"]
                
                if "exposedHeaders" in rule:
                    aws_rule["ExposedHeaders"] = rule["exposedHeaders"]
                
                if "maxAgeSeconds" in rule:
                    aws_rule["MaxAgeSeconds"] = rule["maxAgeSeconds"]
                
                cors_config["CORSRules"].append(aws_rule)
            
            self.client.put_bucket_cors(
                Bucket=name,
                CORSConfiguration=cors_config,
            )
            logger.info(f"Set CORS configuration for bucket {name}")
        except ClientError as e:
            logger.error(f"Failed to set CORS configuration for bucket {name}: {e}")
            raise

    def delete_bucket_cors(self, name: str) -> None:
        """Delete bucket CORS configuration."""
        try:
            self.client.delete_bucket_cors(Bucket=name)
            logger.info(f"Deleted CORS configuration for bucket {name}")
        except ClientError as e:
            # Ignore if CORS doesn't exist
            if e.response.get("Error", {}).get("Code") == "NoSuchCORSConfiguration":
                logger.debug(f"No CORS configuration to delete for bucket {name}")
                return
            logger.error(f"Failed to delete CORS configuration for bucket {name}: {e}")
            raise

    def test_connectivity(self) -> bool:
        """Test connectivity to the provider."""
        try:
            self.client.list_buckets()
            return True
        except Exception as e:
            logger.error(f"Connectivity test failed: {e}")
            return False
    
    def create_user(self, name: str, policy: dict[str, Any] | None = None) -> dict[str, Any]:
        """Create an IAM user.

        Args:
            name: User name
            policy: Optional inline policy document

        Returns:
            User creation response
        """
        logger.info(f"Starting user creation for {name}")
        if not self.iam_client:
            logger.error("IAM client not initialized - IAM endpoint not configured")
            raise ValueError("IAM endpoint not configured")

        try:
            logger.info(f"Calling IAM create_user for {name}")
            response = self.iam_client.create_user(UserName=name)
            logger.info(f"Successfully created IAM user {name}: {response}")

            if policy:
                import json
                logger.info(f"Policy provided for user {name}: {policy}")
                # Convert CRD policy format to AWS format
                aws_policy = self._convert_policy_to_aws_format(policy)
                logger.info(f"Converted policy for user {name}: {aws_policy}")
                policy_json = json.dumps(aws_policy)
                logger.info(f"Policy JSON for user {name}: {policy_json}")

                logger.info(f"Calling put_user_policy for user {name}")
                try:
                    put_response = self.iam_client.put_user_policy(
                        UserName=name,
                        PolicyName=f"{name}-policy",
                        PolicyDocument=policy_json,
                    )
                    logger.info(f"put_user_policy response: {put_response}")
                    logger.info(f"Successfully attached policy to user {name}")

                    # Verify policy was attached
                    logger.info(f"Verifying policy attachment for user {name}")
                    try:
                        verify_response = self.iam_client.get_user_policy(
                            UserName=name,
                            PolicyName=f"{name}-policy",
                        )
                        logger.info(f"Policy verification successful: {verify_response}")
                    except ClientError as verify_error:
                        logger.warning(f"Could not verify policy attachment: {verify_error}")
                        logger.warning(f"Verify error details: {verify_error.response}")
                except ClientError as e:
                    logger.error(f"Failed to attach policy to user {name}: {e}")
                    logger.error(f"Policy attachment error details: {e.response}")
                    raise
            else:
                logger.info(f"No policy provided for user {name}")

            return response
        except ClientError as e:
            logger.error(f"Failed to create user {name}: {e}")
            logger.error(f"User creation error details: {e.response}")
            raise
    
    def delete_user(self, name: str) -> None:
        """Delete an IAM user.
        
        This method will first delete all access keys and inline policies
        associated with the user before deleting the user itself.
        
        Args:
            name: User name
        """
        if not self.iam_client:
            raise ValueError("IAM endpoint not configured")
        
        try:
            # First, delete all access keys
            try:
                access_keys = self.list_access_keys(name)
                for access_key_id in access_keys:
                    try:
                        self.delete_access_key(name, access_key_id)
                        logger.info(f"Deleted access key {access_key_id} for user {name}")
                    except ClientError as e:
                        logger.warning(f"Failed to delete access key {access_key_id}: {e}")
            except ClientError as e:
                logger.warning(f"Failed to list access keys for user {name}: {e}")
            
            # Then, delete all inline policies
            try:
                policies = self.list_user_policies(name)
                for policy_name in policies:
                    try:
                        self.delete_user_policy(name, policy_name)
                        logger.info(f"Deleted policy {policy_name} from user {name}")
                    except ClientError as e:
                        logger.warning(f"Failed to delete policy {policy_name}: {e}")
            except ClientError as e:
                logger.warning(f"Failed to list policies for user {name}: {e}")
            
            # Finally, delete the user
            self.iam_client.delete_user(UserName=name)
            logger.info(f"Deleted user {name}")
        except ClientError as e:
            logger.error(f"Failed to delete user {name}: {e}")
            raise
    
    def create_access_key(self, user_name: str) -> dict[str, Any]:
        """Create access keys for a user.
        
        Args:
            user_name: User name
            
        Returns:
            Access key creation response
        """
        if not self.iam_client:
            raise ValueError("IAM endpoint not configured")
        
        try:
            response = self.iam_client.create_access_key(UserName=user_name)
            return response
        except ClientError as e:
            logger.error(f"Failed to create access key for user {user_name}: {e}")
            raise
    
    def list_access_keys(self, user_name: str) -> list[str]:
        """List all access keys for a user.
        
        Args:
            user_name: User name
            
        Returns:
            List of access key IDs
        """
        if not self.iam_client:
            raise ValueError("IAM endpoint not configured")
        
        try:
            response = self.iam_client.list_access_keys(UserName=user_name)
            return [key["AccessKeyId"] for key in response.get("AccessKeyMetadata", [])]
        except ClientError as e:
            logger.error(f"Failed to list access keys for user {user_name}: {e}")
            raise
    
    def delete_access_key(self, user_name: str, access_key_id: str) -> None:
        """Delete an access key.
        
        Args:
            user_name: User name
            access_key_id: Access key ID to delete
        """
        if not self.iam_client:
            raise ValueError("IAM endpoint not configured")
        
        try:
            self.iam_client.delete_access_key(UserName=user_name, AccessKeyId=access_key_id)
        except ClientError as e:
            logger.error(f"Failed to delete access key {access_key_id}: {e}")
            raise
    
    def list_user_policies(self, user_name: str) -> list[str]:
        """List all inline policies for a user.
        
        Args:
            user_name: User name
            
        Returns:
            List of policy names
        """
        if not self.iam_client:
            raise ValueError("IAM endpoint not configured")
        
        try:
            response = self.iam_client.list_user_policies(UserName=user_name)
            return response.get("PolicyNames", [])
        except ClientError as e:
            logger.error(f"Failed to list policies for user {user_name}: {e}")
            raise
    
    def delete_user_policy(self, user_name: str, policy_name: str) -> None:
        """Delete an inline policy from a user.
        
        Args:
            user_name: User name
            policy_name: Policy name to delete
        """
        if not self.iam_client:
            raise ValueError("IAM endpoint not configured")
        
        try:
            self.iam_client.delete_user_policy(UserName=user_name, PolicyName=policy_name)
        except ClientError as e:
            logger.error(f"Failed to delete policy {policy_name} from user {user_name}: {e}")
            raise
    
    def attach_user_policy(self, user_name: str, policy_name: str) -> None:
        """Attach a managed policy to a user.
        
        Args:
            user_name: User name
            policy_name: Policy name to attach
        """
        if not self.iam_client:
            raise ValueError("IAM endpoint not configured")
        
        try:
            # Try to attach as a managed policy first
            policy_arn = f"arn:aws:iam::*:policy/{policy_name}"
            self.iam_client.attach_user_policy(UserName=user_name, PolicyArn=policy_arn)
            logger.info(f"Attached managed policy {policy_name} to user {user_name}")
        except ClientError as e:
            # If managed policy doesn't exist, try to attach as inline policy
            logger.warning(f"Failed to attach managed policy {policy_name}: {e}")
            # For now, we'll use inline policies instead
            raise
    
    def detach_user_policy(self, user_name: str, policy_name: str) -> None:
        """Detach a managed policy from a user.
        
        Args:
            user_name: User name
            policy_name: Policy name to detach
        """
        if not self.iam_client:
            raise ValueError("IAM endpoint not configured")
        
        try:
            policy_arn = f"arn:aws:iam::*:policy/{policy_name}"
            self.iam_client.detach_user_policy(UserName=user_name, PolicyArn=policy_arn)
            logger.info(f"Detached policy {policy_name} from user {user_name}")
        except ClientError as e:
            logger.error(f"Failed to detach policy {policy_name} from user {user_name}: {e}")
            raise
    
    def attach_user_policy_inline(self, user_name: str, policy_name: str, policy_document: dict[str, Any]) -> None:
        """Attach an inline policy to a user.
        
        Args:
            user_name: User name
            policy_name: Policy name
            policy_document: Policy document dictionary
        """
        if not self.iam_client:
            raise ValueError("IAM endpoint not configured")
        
        try:
            import json
            policy_json = json.dumps(policy_document)
            self.iam_client.put_user_policy(
                UserName=user_name,
                PolicyName=policy_name,
                PolicyDocument=policy_json,
            )
            logger.info(f"Attached inline policy {policy_name} to user {user_name}")
        except ClientError as e:
            logger.error(f"Failed to attach inline policy {policy_name} to user {user_name}: {e}")
            raise
    
    def create_managed_policy(self, policy_name: str, policy_document: dict[str, Any], description: str = "") -> dict[str, Any]:
        """Create a managed IAM policy.
        
        Args:
            policy_name: Policy name
            policy_document: Policy document dictionary
            description: Optional policy description
            
        Returns:
            Policy creation response
        """
        if not self.iam_client:
            raise ValueError("IAM endpoint not configured")
        
        try:
            import json
            policy_json = json.dumps(policy_document)
            
            response = self.iam_client.create_policy(
                PolicyName=policy_name,
                PolicyDocument=policy_json,
                Description=description,
            )
            logger.info(f"Created managed policy {policy_name}")
            return response
        except ClientError as e:
            # If policy already exists, return it
            if e.response.get("Error", {}).get("Code") == "EntityAlreadyExists":
                logger.info(f"Policy {policy_name} already exists, fetching existing policy")
                try:
                    # Get the account ID from error message or use wildcard
                    policy_arn = f"arn:aws:iam::*:policy/{policy_name}"
                    response = self.iam_client.get_policy(PolicyArn=policy_arn)
                    return response
                except Exception:
                    # Try to list and find the policy
                    response = self.iam_client.list_policies(Scope="Local")
                    for policy in response.get("Policies", []):
                        if policy.get("PolicyName") == policy_name:
                            return {"Policy": policy}
                    raise
            logger.error(f"Failed to create managed policy {policy_name}: {e}")
            raise
    
    def delete_managed_policy(self, policy_name: str) -> None:
        """Delete a managed IAM policy.
        
        Args:
            policy_name: Policy name
        """
        if not self.iam_client:
            raise ValueError("IAM endpoint not configured")
        
        try:
            # First, get the policy ARN
            response = self.iam_client.list_policies(Scope="Local")
            policy_arn = None
            for policy in response.get("Policies", []):
                if policy.get("PolicyName") == policy_name:
                    policy_arn = policy.get("Arn")
                    break
            
            if policy_arn:
                self.iam_client.delete_policy(PolicyArn=policy_arn)
                logger.info(f"Deleted managed policy {policy_name}")
            else:
                logger.warning(f"Policy {policy_name} not found")
        except ClientError as e:
            logger.error(f"Failed to delete managed policy {policy_name}: {e}")
            raise
    
    def attach_managed_policy_to_user(self, user_name: str, policy_name: str) -> None:
        """Attach a managed policy to a user.
        
        Args:
            user_name: User name
            policy_name: Policy name
        """
        if not self.iam_client:
            raise ValueError("IAM endpoint not configured")
        
        try:
            # Get the policy ARN
            response = self.iam_client.list_policies(Scope="Local")
            policy_arn = None
            for policy in response.get("Policies", []):
                if policy.get("PolicyName") == policy_name:
                    policy_arn = policy.get("Arn")
                    break
            
            if policy_arn:
                self.iam_client.attach_user_policy(UserName=user_name, PolicyArn=policy_arn)
                logger.info(f"Attached managed policy {policy_name} to user {user_name}")
            else:
                logger.error(f"Policy {policy_name} not found")
                raise ValueError(f"Policy {policy_name} not found")
        except ClientError as e:
            logger.error(f"Failed to attach managed policy {policy_name} to user {user_name}: {e}")
            raise
    
    def detach_managed_policy_from_user(self, user_name: str, policy_name: str) -> None:
        """Detach a managed policy from a user.
        
        Args:
            user_name: User name
            policy_name: Policy name
        """
        if not self.iam_client:
            raise ValueError("IAM endpoint not configured")
        
        try:
            # Get the policy ARN
            response = self.iam_client.list_policies(Scope="Local")
            policy_arn = None
            for policy in response.get("Policies", []):
                if policy.get("PolicyName") == policy_name:
                    policy_arn = policy.get("Arn")
                    break
            
            if policy_arn:
                self.iam_client.detach_user_policy(UserName=user_name, PolicyArn=policy_arn)
                logger.info(f"Detached managed policy {policy_name} from user {user_name}")
            else:
                initial_client_error = ValueError(f"Policy {policy_name} not found")
                logger.warning(f"Policy {policy_name} not found when detaching: {initial_client_error}")
        except ClientError as e:
            logger.error(f"Failed to detach managed policy {policy_name} from user {user_name}: {e}")
            raise

