package tls

import (
	"sync"
	"testing"
)

// TestRollerConcurrentAccess verifies that Roller is safe for concurrent use.
// Run with: go test -race -run TestRollerConcurrentAccess
func TestRollerConcurrentAccess(t *testing.T) {
	roller, err := NewRoller()
	if err != nil {
		t.Fatalf("NewRoller() failed: %v", err)
	}

	const goroutines = 10
	const iterations = 100

	var wg sync.WaitGroup
	wg.Add(goroutines * 2) // readers + writers

	// Concurrent readers: access HelloIDs and use PRNG
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				// Simulate what Dial does: copy HelloIDs under lock, then shuffle
				roller.HelloIDMu.Lock()
				ids := make([]ClientHelloID, len(roller.HelloIDs))
				copy(ids, roller.HelloIDs)
				_ = roller.WorkingHelloID
				roller.HelloIDMu.Unlock()

				// PRNG access outside the lock (tests thread safety of PRNG)
				roller.r.Shuffle(len(ids), func(i, j int) {
					ids[i], ids[j] = ids[j], ids[i]
				})
			}
		}()
	}

	// Concurrent writers: modify HelloIDs and WorkingHelloID
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				roller.HelloIDMu.Lock()
				// Simulate modifying HelloIDs
				if len(roller.HelloIDs) > 0 {
					helloID := roller.HelloIDs[0]
					roller.WorkingHelloID = &helloID
				}
				roller.HelloIDMu.Unlock()
			}
		}(i)
	}

	wg.Wait()
}

// TestPRNGConcurrentAccess verifies the internal PRNG is thread-safe.
// Run with: go test -race -run TestPRNGConcurrentAccess
func TestPRNGConcurrentAccess(t *testing.T) {
	p, err := newPRNG()
	if err != nil {
		t.Fatalf("newPRNG() failed: %v", err)
	}

	const goroutines = 10
	const iterations = 100

	var wg sync.WaitGroup
	wg.Add(goroutines * 4)

	// Concurrent Shuffle calls
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			slice := []int{1, 2, 3, 4, 5}
			for j := 0; j < iterations; j++ {
				p.Shuffle(len(slice), func(a, b int) {
					slice[a], slice[b] = slice[b], slice[a]
				})
			}
		}()
	}

	// Concurrent Intn calls
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_ = p.Intn(100)
			}
		}()
	}

	// Concurrent Read calls
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			buf := make([]byte, 32)
			for j := 0; j < iterations; j++ {
				_, _ = p.Read(buf)
			}
		}()
	}

	// Concurrent Int63n calls
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_ = p.Int63n(1000)
			}
		}()
	}

	wg.Wait()
}
