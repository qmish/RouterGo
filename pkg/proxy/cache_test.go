package proxy

import (
	"testing"
	"time"
)

func TestCacheSetGet(t *testing.T) {
	cache := NewCache(2, 50*time.Millisecond)
	cache.Set("k1", &CacheValue{Status: 200})

	value, ok := cache.Get("k1")
	if !ok || value == nil || value.Status != 200 {
		t.Fatalf("expected cache hit for k1")
	}
	if cache.Size() != 1 {
		t.Fatalf("expected size 1, got %d", cache.Size())
	}
}

func TestCacheExpired(t *testing.T) {
	cache := NewCache(2, 10*time.Millisecond)
	cache.Set("k1", &CacheValue{Status: 200})

	time.Sleep(20 * time.Millisecond)
	if _, ok := cache.Get("k1"); ok {
		t.Fatalf("expected cache miss after expiry")
	}
	value, ok, expired := cache.GetEntry("k1")
	if !ok || !expired || value == nil {
		t.Fatalf("expected expired entry for k1")
	}
}

func TestCacheEvictionLRU(t *testing.T) {
	cache := NewCache(2, time.Second)
	cache.Set("a", &CacheValue{Status: 200})
	cache.Set("b", &CacheValue{Status: 201})

	if _, ok := cache.Get("a"); !ok {
		t.Fatalf("expected a to exist")
	}
	cache.Set("c", &CacheValue{Status: 202})

	if _, ok := cache.Get("b"); ok {
		t.Fatalf("expected b to be evicted")
	}
	if _, ok := cache.Get("a"); !ok {
		t.Fatalf("expected a to remain after LRU update")
	}
	if _, ok := cache.Get("c"); !ok {
		t.Fatalf("expected c to exist")
	}
}

func TestCacheClear(t *testing.T) {
	cache := NewCache(2, time.Second)
	cache.Set("k1", &CacheValue{Status: 200})
	cache.Set("k2", &CacheValue{Status: 201})

	cache.Clear()
	if cache.Size() != 0 {
		t.Fatalf("expected cache size 0 after clear, got %d", cache.Size())
	}
	if _, ok := cache.Get("k1"); ok {
		t.Fatalf("expected cache miss after clear")
	}
}
