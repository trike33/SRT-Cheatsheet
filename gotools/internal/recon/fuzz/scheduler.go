package fuzz

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/trike33/srt-cheatsheet/gotools/internal/ioutil"
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

	perHostIval  time.Duration // 0 = unlimited
	perHostConc  int           // 0 = unlimited
	adaptiveConc bool          // -adaptive-conc: let each host's cap float with observed latency/errors
	maxQueue     int           // per-host backpressure (0 = unbounded)

	feeders     int // outstanding feeder goroutines
	inflightTot int // requests dispatched but not yet finished

	ready    chan hostJob
	gLimiter *rateLimiter
	stop     *atomic.Bool
}

type hostBucket struct {
	name         string
	jobs         []fuzzJob
	inflight     int
	nextAllowed  time.Time     // earliest time this host may be hit again
	throttleIval time.Duration // adaptive backoff added on 429/503 (auto-throttle)

	// live stats for the per-host progress line.
	reqs    atomic.Int64
	matches atomic.Int64

	// adaptive per-host concurrency (-adaptive-conc): AIMD on top of latency.
	adaptMu    sync.Mutex
	concLimit  int     // current adaptive cap (0 = not primed yet)
	emaLatency float64 // ms, exponential moving average
	successRun int     // consecutive clean responses since the last raise
}

type hostJob struct {
	job fuzzJob
	hb  *hostBucket
}

func newScheduler(workers int, perHostIval time.Duration, perHostConc int, gLimiter *rateLimiter, stop *atomic.Bool, adaptiveConc bool) *scheduler {
	return &scheduler{
		byNm:         map[string]*hostBucket{},
		perHostIval:  perHostIval,
		perHostConc:  perHostConc,
		adaptiveConc: adaptiveConc,
		maxQueue:     4096,
		ready:        make(chan hostJob), // unbuffered: bounded by worker count
		gLimiter:     gLimiter,
		stop:         stop,
	}
}

// Adaptive concurrency tuning constants: start conservative, climb slowly
// (one slot every adaptiveStep clean responses in a row), and back off hard
// and immediately the moment a host shows signs of strain.
const (
	adaptiveStart = 4
	adaptiveMax   = 200
	adaptiveStep  = 8
)

// effCap returns the concurrency cap to enforce for hb right now: the static
// -hc ceiling when adaptive concurrency is off, or the tighter of -hc (if
// set) and the host's own adaptive cap when it's on. 0 means unlimited.
func (hb *hostBucket) effCap(staticCap int, adaptive bool) int {
	if !adaptive {
		return staticCap
	}
	hb.adaptMu.Lock()
	c := hb.concLimit
	hb.adaptMu.Unlock()
	if c <= 0 {
		c = adaptiveStart
	}
	if staticCap > 0 && staticCap < c {
		return staticCap
	}
	return c
}

// adaptRecord feeds one completed request's outcome into the AIMD controller:
// ok is false for a transport error or a 429/503 (shrink immediately,
// multiplicative decrease); otherwise elapsed is compared against this host's
// recent average latency -- a request much slower than usual is an early
// overload signal even before anything starts erroring, so the cap holds and
// eases back a step instead of climbing further. Only after a run of clean,
// on-pace responses does the cap grow, one slot at a time.
func (hb *hostBucket) adaptRecord(ok bool, elapsed time.Duration) {
	hb.adaptMu.Lock()
	defer hb.adaptMu.Unlock()
	if hb.concLimit <= 0 {
		hb.concLimit = adaptiveStart
	}
	ms := float64(elapsed.Milliseconds())
	if hb.emaLatency == 0 {
		hb.emaLatency = ms
	} else {
		hb.emaLatency = hb.emaLatency*0.8 + ms*0.2
	}
	if !ok {
		hb.concLimit = max(1, hb.concLimit*2/3)
		hb.successRun = 0
		return
	}
	if hb.emaLatency > 0 && ms > hb.emaLatency*2 {
		hb.concLimit = max(1, hb.concLimit-1)
		hb.successRun = 0
		return
	}
	hb.successRun++
	if hb.successRun >= adaptiveStep && hb.concLimit < adaptiveMax {
		hb.concLimit++
		hb.successRun = 0
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

// throttle widens a host's rate after a 429/503 (exponential backoff, capped).
func (s *scheduler) throttle(hb *hostBucket) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if hb.throttleIval == 0 {
		hb.throttleIval = 100 * time.Millisecond
		ioutil.Warn("auto-throttle: %s returned 429/503, backing off", hb.name)
	} else {
		hb.throttleIval *= 2
	}
	if hb.throttleIval > 5*time.Second {
		hb.throttleIval = 5 * time.Second
	}
}

// relax decays a host's throttle back toward its base rate on a good response.
func (s *scheduler) relax(hb *hostBucket) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if hb.throttleIval == 0 {
		return
	}
	hb.throttleIval = hb.throttleIval * 9 / 10
	if hb.throttleIval < 20*time.Millisecond {
		hb.throttleIval = 0
	}
}

// hostsSnapshot returns the current host buckets, for the progress line.
func (s *scheduler) hostsSnapshot() []*hostBucket {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*hostBucket, len(s.order))
	copy(out, s.order)
	return out
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
		if capN := hb.effCap(s.perHostConc, s.adaptiveConc); capN > 0 && hb.inflight >= capN {
			continue
		}
		// Effective interval = configured per-host rate, widened by any adaptive
		// throttle currently applied to this host.
		effIval := s.perHostIval
		if hb.throttleIval > effIval {
			effIval = hb.throttleIval
		}
		if effIval > 0 && now.Before(hb.nextAllowed) {
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
		if effIval > 0 {
			base := hb.nextAllowed
			if base.Before(now) {
				base = now
			}
			hb.nextAllowed = base.Add(effIval)
		}
		s.rr = (s.rr + k + 1) % n
		return hostJob{job: job, hb: hb}, true, 0
	}
	if minWait == 0 {
		minWait = 2 * time.Millisecond
	}
	return hostJob{}, false, minWait
}
