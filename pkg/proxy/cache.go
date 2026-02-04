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
	Status  int
	Headers map[string]string
	Body    []byte
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
	c.mu.Lock()
	defer c.mu.Unlock()
	elem, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	entry := elem.Value.(*cacheEntry)
	if time.Now().After(entry.expiresAt) {
		c.order.Remove(elem)
		delete(c.entries, key)
		return nil, false
	}
	c.order.MoveToFront(elem)
	return entry.value, true
}

func (c *Cache) Set(key string, value *CacheValue) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if elem, ok := c.entries[key]; ok {
		entry := elem.Value.(*cacheEntry)
		entry.value = value
		entry.expiresAt = time.Now().Add(c.ttl)
		c.order.MoveToFront(elem)
		return
	}
	entry := &cacheEntry{
		key:       key,
		value:     value,
		expiresAt: time.Now().Add(c.ttl),
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
