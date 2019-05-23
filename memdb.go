package jwt_sessions

import (
	"github.com/kataras/iris/sessions"
	"github.com/kataras/iris/core/memstore"
	"sync"
	"time"
)


// This is an exact port of Iris sessions' MemDB, but this one is public.
// (hopefully I can reuse the other 3 database types).


type MemDB struct {
	values map[string]*memstore.Store
	mu     sync.RWMutex
}

var _ sessions.Database = (*MemDB)(nil)

func NewMemDB() sessions.Database { return &MemDB{values: make(map[string]*memstore.Store)} }

func (s *MemDB) Acquire(sid string, expires time.Duration) sessions.LifeTime {
	s.mu.Lock()
	s.values[sid] = new(memstore.Store)
	s.mu.Unlock()
	return sessions.LifeTime{}
}

// Do nothing, the `LifeTime` of the Session will be managed by the callers automatically on memory-based storage.
func (s *MemDB) OnUpdateExpiration(string, time.Duration) error { return nil }

// immutable depends on the store, it may not implement it at all.
func (s *MemDB) Set(sid string, lifetime sessions.LifeTime, key string, value interface{}, immutable bool) {
	s.mu.RLock()
	s.values[sid].Save(key, value, immutable)
	s.mu.RUnlock()
}

func (s *MemDB) Get(sid string, key string) interface{} {
	s.mu.RLock()
	v := s.values[sid].Get(key)
	s.mu.RUnlock()

	return v
}

func (s *MemDB) Visit(sid string, cb func(key string, value interface{})) {
	s.values[sid].Visit(cb)
}

func (s *MemDB) Len(sid string) int {
	s.mu.RLock()
	n := s.values[sid].Len()
	s.mu.RUnlock()

	return n
}

func (s *MemDB) Delete(sid string, key string) (deleted bool) {
	s.mu.RLock()
	deleted = s.values[sid].Remove(key)
	s.mu.RUnlock()
	return
}

func (s *MemDB) Clear(sid string) {
	s.mu.Lock()
	s.values[sid].Reset()
	s.mu.Unlock()
}

func (s *MemDB) Release(sid string) {
	s.mu.Lock()
	delete(s.values, sid)
	s.mu.Unlock()
}

