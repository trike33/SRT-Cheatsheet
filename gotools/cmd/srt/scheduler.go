package main

import (
	"sync"
	"sync/atomic"
	"time"
)

// scheduler spreads fuzz work fairly across multiple hosts. A single dispatcher
// goroutine round-robins over the hosts and hands ready jobs to a shared worker
// pool, enforcing:
//
//   - per-host pacing (perHostIval): at most one request per interval per host,
//     so no single target is flooded;
//   - per-host concurrency (perHostConc): cap simultaneous requests per host;
//   - global concurrency: the number of workers draining `ready`;
//   - an optional global rate cap (gLimiter) to protect your own uplink.
//
// Because the dispatcher interleaves hosts instead of draining one wordlist
// before starting the next host, web1/web2/web3 all make progress at once
// rather than web1 getting hammered first.
type scheduler struct {
	mu    sync.Mutex
	order []*hostBucket
	byNm  map[string]*hostBucket
	rr    int

	perHostIval time.Duration // 0 = unlimited
	perHostConc int           // 0 = unlimited
	maxQueue    int           // per-host backpressure (0 = unbounded)

	feeders     int // outstanding feeder goroutines
	inflightTot int // requests dispatched but not yet finished

	ready    chan hostJob
	gLimiter *rateLimiter
	stop     *atomic.Bool
}

type hostBucket struct {
	name        string
	jobs        []fuzzJob
	inflight    int
	nextAllowed time.Time // earliest time this host may be hit again
}

type hostJob struct {
	job fuzzJob
	hb  *hostBucket
}

func newScheduler(workers int, perHostIval time.Duration, perHostConc int, gLimiter *rateLimiter, stop *atomic.Bool) *scheduler {
	return &scheduler{
		byNm:        map[string]*hostBucket{},
		perHostIval: perHostIval,
		perHostConc: perHostConc,
		maxQueue:    4096,
		ready:       make(chan hostJob), // unbuffered: bounded by worker count
		gLimiter:    gLimiter,
		stop:        stop,
	}
}

// hostBucket returns (creating if needed) the bucket for a host name.
func (s *scheduler) hostBucket(name string) *hostBucket {
	s.mu.Lock()
	defer s.mu.Unlock()
	hb, ok := s.byNm[name]
	if !ok {
		hb = &hostBucket{name: name}
		s.byNm[name] = hb
		s.order = append(s.order, hb)
	}
	return hb
}

func (s *scheduler) addFeeder()  { s.mu.Lock(); s.feeders++; s.mu.Unlock() }
func (s *scheduler) feederDone() { s.mu.Lock(); s.feeders--; s.mu.Unlock() }

// pushJob appends a job to a host's queue, applying backpressure so a giant
// wordlist across many hosts doesn't balloon memory.
func (s *scheduler) pushJob(hb *hostBucket, j fuzzJob) {
	for {
		if s.stop.Load() {
			return
		}
		s.mu.Lock()
		if s.maxQueue == 0 || len(hb.jobs) < s.maxQueue {
			hb.jobs = append(hb.jobs, j)
			s.mu.Unlock()
			return
		}
		s.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
}

// finish records that a dispatched request completed, freeing host + global slots.
func (s *scheduler) finish(hb *hostBucket) {
	s.mu.Lock()
	hb.inflight--
	s.inflightTot--
	s.mu.Unlock()
}

// dispatch is the scheduling loop; it closes `ready` when all work is done.
func (s *scheduler) dispatch() {
	for {
		s.mu.Lock()
		if s.doneLocked() {
			s.mu.Unlock()
			break
		}
		hj, ok, wait := s.pickLocked()
		s.mu.Unlock()

		if !ok {
			if wait > 25*time.Millisecond {
				wait = 25 * time.Millisecond
			}
			if wait < time.Millisecond {
				wait = time.Millisecond
			}
			time.Sleep(wait)
			continue
		}
		if s.gLimiter != nil {
			s.gLimiter.wait() // global rate cap across all hosts
		}
		s.ready <- hj
	}
	close(s.ready)
}

func (s *scheduler) doneLocked() bool {
	if s.feeders != 0 || s.inflightTot != 0 {
		return false
	}
	for _, hb := range s.order {
		if len(hb.jobs) > 0 {
			return false
		}
	}
	return true
}

// pickLocked selects the next ready job round-robin. If nothing is ready, it
// returns the suggested sleep until the nearest host's rate window opens.
func (s *scheduler) pickLocked() (hostJob, bool, time.Duration) {
	n := len(s.order)
	if n == 0 {
		return hostJob{}, false, 2 * time.Millisecond
	}
	now := time.Now()
	var minWait time.Duration
	for k := 0; k < n; k++ {
		hb := s.order[(s.rr+k)%n]
		if len(hb.jobs) == 0 {
			continue
		}
		if s.perHostConc > 0 && hb.inflight >= s.perHostConc {
			continue
		}
		if s.perHostIval > 0 && now.Before(hb.nextAllowed) {
			w := hb.nextAllowed.Sub(now)
			if minWait == 0 || w < minWait {
				minWait = w
			}
			continue
		}
		job := hb.jobs[0]
		hb.jobs = hb.jobs[1:]
		hb.inflight++
		s.inflightTot++
		if s.perHostIval > 0 {
			base := hb.nextAllowed
			if base.Before(now) {
				base = now
			}
			hb.nextAllowed = base.Add(s.perHostIval)
		}
		s.rr = (s.rr + k + 1) % n
		return hostJob{job: job, hb: hb}, true, 0
	}
	if minWait == 0 {
		minWait = 2 * time.Millisecond
	}
	return hostJob{}, false, minWait
}
