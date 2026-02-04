package proxy

import (
	"container/list"
	"sync"
	"time"
)

type cacheEntry struct {
	key       string
	value     *CacheValue
	expiresAt time.Time
}

type CacheValue struct {
	Status        int
	Headers       map[string]string
	Body          []byte
	StoredAt      time.Time
	MaxAgeSeconds int
	VaryHeaders   map[string]string
	ETag          string
}

type Cache struct {
	mu       sync.Mutex
	entries  map[string]*list.Element
	order    *list.List
	capacity int
	ttl      time.Duration
}

func NewCache(capacity int, ttl time.Duration) *Cache {
	if capacity <= 0 {
		capacity = 100
	}
	if ttl == 0 {
		ttl = 60 * time.Second
	}
	return &Cache{
		entries:  map[string]*list.Element{},
		order:    list.New(),
		capacity: capacity,
		ttl:      ttl,
	}
}

func (c *Cache) Get(key string) (*CacheValue, bool) {
	value, ok, expired := c.GetEntry(key)
	if !ok || expired {
		return nil, false
	}
	return value, true
}

func (c *Cache) GetEntry(key string) (*CacheValue, bool, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	elem, ok := c.entries[key]
	if !ok {
		return nil, false, false
	}
	entry := elem.Value.(*cacheEntry)
	expired := time.Now().After(entry.expiresAt)
	if time.Now().After(entry.expiresAt) {
		return entry.value, true, true
	}
	c.order.MoveToFront(elem)
	return entry.value, true, expired
}

func (c *Cache) Set(key string, value *CacheValue) {
	c.SetWithTTL(key, value, c.ttl)
}

func (c *Cache) SetWithTTL(key string, value *CacheValue, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ttl <= 0 {
		ttl = c.ttl
	}
	if elem, ok := c.entries[key]; ok {
		entry := elem.Value.(*cacheEntry)
		entry.value = value
		entry.expiresAt = time.Now().Add(ttl)
		c.order.MoveToFront(elem)
		return
	}
	entry := &cacheEntry{
		key:       key,
		value:     value,
		expiresAt: time.Now().Add(ttl),
	}
	elem := c.order.PushFront(entry)
	c.entries[key] = elem
	if c.order.Len() > c.capacity {
		tail := c.order.Back()
		if tail != nil {
			c.order.Remove(tail)
			old := tail.Value.(*cacheEntry)
			delete(c.entries, old.key)
		}
	}
}

func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = map[string]*list.Element{}
	c.order.Init()
}

func (c *Cache) Size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}
