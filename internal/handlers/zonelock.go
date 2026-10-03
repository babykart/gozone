package handlers

import "sync"

// zoneLocks serializes read-modify-write record mutations per zone within
// this process. The record write paths fetch the zone's RRSets, merge the
// submission into them and PATCH the result back; two concurrent mutations
// on the same RRSet used to interleave their fetches, and the second PATCH
// silently dropped the first's records. Holding a per-zone mutex across the
// whole fetch→merge→write sequence closes that window in-process, while
// mutations to different zones proceed in parallel.
//
// Scope: this guards one GoZone process. Multi-instance deployments share
// PowerDNS state and would need coordination at the database or PowerDNS
// level; the mutex is the in-process minimum.
//
// The lock map is write-once per zone and never pruned: a mutex is a few
// dozen bytes and the zone count is bounded by what PowerDNS serves.
type zoneLocks struct {
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

// Lock acquires the mutex for zoneID and returns its release function, so
// the whole request-scoped critical section is one line at the call site:
//
//	defer h.zoneLocks.Lock(zoneID)()
//
// The map is created lazily so a zero-value zoneLocks (an unwired Handler in
// a test) is usable without an explicit constructor.
func (z *zoneLocks) Lock(zoneID string) func() {
	z.mu.Lock()
	if z.locks == nil {
		z.locks = make(map[string]*sync.Mutex)
	}
	m, ok := z.locks[zoneID]
	if !ok {
		m = &sync.Mutex{}
		z.locks[zoneID] = m
	}
	z.mu.Unlock()
	m.Lock()
	return m.Unlock
}
