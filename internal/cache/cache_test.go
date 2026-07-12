package cache

import (
	"testing"
	"time"
)

func TestCache_SetGet(t *testing.T) {
	c := New[string](5 * time.Second)
	defer c.Stop()

	c.Set("k1", "hello")

	v, ok := c.Get("k1")
	if !ok {
		t.Fatal("expected key k1 to be present")
	}
	if v != "hello" {
		t.Errorf("got %q, want hello", v)
	}
}

func TestCache_GetMissing(t *testing.T) {
	c := New[string](5 * time.Second)
	defer c.Stop()

	_, ok := c.Get("nonexistent")
	if ok {
		t.Error("expected missing key to return false")
	}
}

func TestCache_Expiry(t *testing.T) {
	c := New[string](10 * time.Millisecond)
	defer c.Stop()

	c.Set("k1", "hello")
	time.Sleep(15 * time.Millisecond)

	_, ok := c.Get("k1")
	if ok {
		t.Error("expected expired key to return false")
	}
}

func TestCache_GetEvictsExpiredEntry(t *testing.T) {
	// REVIEW.md L-16a: Get must proactively delete an expired entry instead
	// of leaving it for the background sweep. Verify by inspecting the map
	// directly (Len() filters by expiry, so it cannot distinguish "deleted"
	// from "still present but expired").
	c := New[string](10 * time.Millisecond)
	defer c.Stop()

	c.Set("k1", "hello")
	c.Set("k2", "world")
	time.Sleep(15 * time.Millisecond)

	if _, ok := c.Get("k1"); ok {
		t.Fatal("expected expired key k1 to return false")
	}

	c.mu.RLock()
	remaining := len(c.items)
	c.mu.RUnlock()
	if remaining != 1 {
		t.Errorf("expected only the un-touched k2 to remain, got %d entries", remaining)
	}

	// k2 is expired but was not touched by Get: it stays until a Get or sweep.
	c.mu.RLock()
	_, hasK2 := c.items["k2"]
	c.mu.RUnlock()
	if !hasK2 {
		t.Error("k2 should still be present (only Get-touched entries are proactively evicted)")
	}
}

func TestCache_LenExpired(t *testing.T) {
	c := New[string](10 * time.Millisecond)
	defer c.Stop()

	c.Set("k1", "hello")
	c.Set("k2", "world")

	if c.Len() != 2 {
		t.Fatalf("expected 2 items, got %d", c.Len())
	}

	time.Sleep(15 * time.Millisecond)

	if c.Len() != 0 {
		t.Errorf("expected 0 non-expired items after expiry, got %d", c.Len())
	}
}

func TestCache_Delete(t *testing.T) {
	c := New[string](5 * time.Second)
	defer c.Stop()

	c.Set("k1", "hello")
	c.Delete("k1")

	_, ok := c.Get("k1")
	if ok {
		t.Error("expected deleted key to return false")
	}
}

func TestCache_Clear(t *testing.T) {
	c := New[int](5 * time.Second)
	defer c.Stop()

	c.Set("a", 1)
	c.Set("b", 2)
	c.Set("c", 3)

	if c.Len() != 3 {
		t.Fatalf("expected 3 items, got %d", c.Len())
	}

	c.Clear()

	if c.Len() != 0 {
		t.Errorf("expected 0 items after clear, got %d", c.Len())
	}
}

func TestCache_Concurrent(t *testing.T) {
	c := New[int](5 * time.Second)
	defer c.Stop()

	done := make(chan struct{})

	go func() {
		for i := 0; i < 1000; i++ {
			c.Set("key", i)
		}
		done <- struct{}{}
	}()

	go func() {
		for i := 0; i < 1000; i++ {
			c.Get("key")
		}
		done <- struct{}{}
	}()

	<-done
	<-done
}

func TestCache_GenericTypes(t *testing.T) {
	intCache := New[int](5 * time.Second)
	defer intCache.Stop()

	intCache.Set("n", 42)
	v1, ok1 := intCache.Get("n")
	if !ok1 || v1 != 42 {
		t.Errorf("int cache: got %d, %v, want 42, true", v1, ok1)
	}

	strCache := New[string](5 * time.Second)
	defer strCache.Stop()

	strCache.Set("s", "test")
	v2, ok2 := strCache.Get("s")
	if !ok2 || v2 != "test" {
		t.Errorf("string cache: got %q, %v, want test, true", v2, ok2)
	}

	sliceCache := New[[]int](5 * time.Second)
	defer sliceCache.Stop()

	sliceCache.Set("sl", []int{1, 2, 3})
	v3, ok3 := sliceCache.Get("sl")
	if !ok3 || len(v3) != 3 {
		t.Errorf("slice cache: got %v, %v, want [1 2 3], true", v3, ok3)
	}
}

func TestCache_Sweep(t *testing.T) {
	c := New[string](50 * time.Millisecond)
	defer c.Stop()

	c.Set("k1", "a")
	c.Set("k2", "b")

	if c.Len() != 2 {
		t.Fatalf("expected 2 items, got %d", c.Len())
	}

	time.Sleep(120 * time.Millisecond)

	if c.Len() != 0 {
		t.Errorf("expected 0 after sweep, got %d", c.Len())
	}
}

func TestCache_Stop(t *testing.T) {
	c := New[string](5 * time.Second)
	c.Stop()

	c.Set("k1", "hello")
	v, ok := c.Get("k1")
	if !ok || v != "hello" {
		t.Errorf("expected cache to still work after Stop, got %v, %v", v, ok)
	}
}
