"""Tests for cache utilities."""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from wasabi_s3_operator.utils.cache import (
    get_cached_object,
    invalidate_cache,
    make_cache_key,
    set_cached_object,
)


class TestCacheKey:
    """Test cases for make_cache_key function."""

    def test_make_cache_key(self):
        """Test making cache key."""
        key = make_cache_key("Provider", "default", "wasabi-provider")
        assert key == "Provider:default:wasabi-provider"

    def test_make_cache_key_different_values(self):
        """Test cache keys are unique for different resources."""
        key1 = make_cache_key("Bucket", "ns1", "bucket1")
        key2 = make_cache_key("Bucket", "ns2", "bucket1")
        key3 = make_cache_key("Provider", "ns1", "bucket1")
        
        assert key1 != key2
        assert key1 != key3
        assert key2 != key3


class TestCacheOperations:
    """Test cases for cache get/set operations."""

    def setup_method(self):
        """Clear cache before each test."""
        invalidate_cache()

    def test_set_and_get_cached_object(self):
        """Test setting and getting cached object."""
        key = "test:key:1"
        obj = {"name": "test", "value": 123}
        
        set_cached_object(key, obj)
        result = get_cached_object(key)
        
        assert result == obj

    def test_get_nonexistent_object(self):
        """Test getting non-existent cached object returns None."""
        result = get_cached_object("nonexistent:key")
        assert result is None

    def test_cache_expiration(self):
        """Test that cached objects expire after TTL."""
        key = "test:key:expire"
        obj = {"data": "test"}
        
        # Set TTL to 0.1 seconds for testing
        with patch("wasabi_s3_operator.utils.cache._cache_ttl", 0.1):
            set_cached_object(key, obj)
            
            # Should be available immediately
            assert get_cached_object(key) == obj
            
            # Wait for expiration
            time.sleep(0.2)
            
            # Should be expired
            assert get_cached_object(key) is None

    def test_cache_not_expired(self):
        """Test that cached objects don't expire before TTL."""
        key = "test:key:valid"
        obj = {"data": "test"}
        
        with patch("wasabi_s3_operator.utils.cache._cache_ttl", 10.0):
            set_cached_object(key, obj)
            
            # Should be available
            assert get_cached_object(key) == obj

    def test_cache_overwrite(self):
        """Test that setting same key overwrites previous value."""
        key = "test:key:overwrite"
        obj1 = {"version": 1}
        obj2 = {"version": 2}
        
        set_cached_object(key, obj1)
        set_cached_object(key, obj2)
        
        result = get_cached_object(key)
        assert result == obj2
        assert result["version"] == 2


class TestCacheInvalidation:
    """Test cases for cache invalidation."""

    def setup_method(self):
        """Clear cache before each test."""
        invalidate_cache()

    def test_invalidate_all_cache(self):
        """Test invalidating all cache entries."""
        set_cached_object("key1", {"data": 1})
        set_cached_object("key2", {"data": 2})
        set_cached_object("key3", {"data": 3})
        
        invalidate_cache()
        
        assert get_cached_object("key1") is None
        assert get_cached_object("key2") is None
        assert get_cached_object("key3") is None

    def test_invalidate_cache_with_pattern(self):
        """Test invalidating cache entries matching pattern."""
        set_cached_object("Provider:default:p1", {"name": "p1"})
        set_cached_object("Provider:default:p2", {"name": "p2"})
        set_cached_object("Bucket:default:b1", {"name": "b1"})
        
        invalidate_cache("Provider")
        
        # Provider entries should be invalidated
        assert get_cached_object("Provider:default:p1") is None
        assert get_cached_object("Provider:default:p2") is None
        
        # Bucket entry should still exist
        assert get_cached_object("Bucket:default:b1") is not None

    def test_invalidate_cache_namespace_pattern(self):
        """Test invalidating cache entries for specific namespace."""
        set_cached_object("Provider:ns1:p1", {"name": "p1"})
        set_cached_object("Provider:ns2:p2", {"name": "p2"})
        set_cached_object("Bucket:ns1:b1", {"name": "b1"})
        
        invalidate_cache("ns1")
        
        # ns1 entries should be invalidated
        assert get_cached_object("Provider:ns1:p1") is None
        assert get_cached_object("Bucket:ns1:b1") is None
        
        # ns2 entry should still exist
        assert get_cached_object("Provider:ns2:p2") is not None

    def test_invalidate_cache_no_match(self):
        """Test invalidating cache with pattern that doesn't match."""
        set_cached_object("Provider:default:p1", {"name": "p1"})
        set_cached_object("Bucket:default:b1", {"name": "b1"})
        
        invalidate_cache("User")
        
        # Nothing should be invalidated
        assert get_cached_object("Provider:default:p1") is not None
        assert get_cached_object("Bucket:default:b1") is not None

    def test_invalidate_empty_cache(self):
        """Test invalidating empty cache doesn't error."""
        invalidate_cache()  # Should not raise error
        invalidate_cache("pattern")  # Should not raise error


class TestCacheTypes:
    """Test caching different data types."""

    def setup_method(self):
        """Clear cache before each test."""
        invalidate_cache()

    def test_cache_dict(self):
        """Test caching dictionary."""
        obj = {"key": "value", "nested": {"data": 123}}
        set_cached_object("test:dict", obj)
        assert get_cached_object("test:dict") == obj

    def test_cache_list(self):
        """Test caching list."""
        obj = [1, 2, 3, 4, 5]
        set_cached_object("test:list", obj)
        assert get_cached_object("test:list") == obj

    def test_cache_string(self):
        """Test caching string."""
        obj = "test string value"
        set_cached_object("test:str", obj)
        assert get_cached_object("test:str") == obj

    def test_cache_integer(self):
        """Test caching integer."""
        obj = 42
        set_cached_object("test:int", obj)
        assert get_cached_object("test:int") == obj

    def test_cache_none(self):
        """Test caching None value."""
        set_cached_object("test:none", None)
        # Getting None should return the cached None, not missing key
        result = get_cached_object("test:none")
        # Note: with current implementation, we can't distinguish
        # between cached None and missing key, both return None
        assert result is None
