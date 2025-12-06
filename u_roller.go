package tls

import (
	"net"
	"sync"
	"time"
)

// Roller provides automatic HelloID selection by cycling through a list of
// ClientHelloIDs until a working one is found. Once a working HelloID is
// discovered, it is reused for subsequent connections.
//
// # Thread Safety
//
// Roller is safe for concurrent use by multiple goroutines. The implementation
// uses the following synchronization strategy:
//
//   - HelloIDs and WorkingHelloID are protected by HelloIDMu. Any access to
//     these fields must hold this mutex.
//
//   - The internal PRNG (r field) has its own internal synchronization via
//     mutex-protected methods (Shuffle, Intn, etc.). This allows the PRNG
//     to be safely called outside the HelloIDMu lock without introducing
//     race conditions.
//
//   - TcpDialTimeout and TlsHandshakeTimeout are only written during
//     construction and are read-only thereafter; no synchronization needed.
//
// The Dial method creates a local copy of HelloIDs while holding the lock,
// then releases the lock before performing network operations. This allows
// concurrent Dial calls to proceed independently without blocking each other
// during potentially slow network operations.
type Roller struct {
	// HelloIDs is the list of ClientHelloIDs to try. Protected by HelloIDMu.
	HelloIDs []ClientHelloID
	// HelloIDMu protects HelloIDs and WorkingHelloID.
	HelloIDMu sync.Mutex
	// WorkingHelloID caches the last successful HelloID. Protected by HelloIDMu.
	WorkingHelloID *ClientHelloID
	// TcpDialTimeout is the timeout for TCP connection. Read-only after construction.
	TcpDialTimeout time.Duration
	// TlsHandshakeTimeout is the timeout for TLS handshake. Read-only after construction.
	TlsHandshakeTimeout time.Duration
	// r is the internal PRNG. It has internal synchronization and is safe for
	// concurrent use without external locking.
	r *prng
}

// NewRoller creates a new Roller with a default set of HelloIDs to cycle through
// until a working one is found. The default set includes HelloChrome_Auto,
// HelloFirefox_Auto, HelloIOS_Auto, and HelloRandomized.
//
// NewRoller initializes an internal thread-safe PRNG for shuffling HelloIDs.
// The returned Roller is safe for concurrent use by multiple goroutines.
func NewRoller() (*Roller, error) {
	r, err := newPRNG()
	if err != nil {
		return nil, err
	}

	tcpDialTimeoutInc := r.Intn(14)
	tcpDialTimeoutInc = 7 + tcpDialTimeoutInc

	tlsHandshakeTimeoutInc := r.Intn(20)
	tlsHandshakeTimeoutInc = 11 + tlsHandshakeTimeoutInc

	return &Roller{
		HelloIDs: []ClientHelloID{
			HelloChrome_Auto,
			HelloFirefox_Auto,
			HelloIOS_Auto,
			HelloRandomized,
		},
		TcpDialTimeout:      time.Second * time.Duration(tcpDialTimeoutInc),
		TlsHandshakeTimeout: time.Second * time.Duration(tlsHandshakeTimeoutInc),
		r:                   r,
	}, nil
}

// Dial attempts to establish connection to given address using different HelloIDs.
// If a working HelloID is found, it is used again for subsequent Dials.
// If tcp connection fails or all HelloIDs are tried, returns with last error.
//
// Dial is safe for concurrent use. Multiple goroutines may call Dial simultaneously
// on the same Roller instance.
//
// Usage examples:
//
//	Dial("tcp4", "google.com:443", "google.com")
//	Dial("tcp", "10.23.144.22:443", "mywebserver.org")
func (c *Roller) Dial(network, addr, serverName string) (*UConn, error) {
	// Acquire lock to safely copy HelloIDs and WorkingHelloID.
	// The lock is released before network I/O to allow concurrent Dial calls.
	c.HelloIDMu.Lock()
	helloIDs := make([]ClientHelloID, len(c.HelloIDs))
	copy(helloIDs, c.HelloIDs)
	workingHelloId := c.WorkingHelloID
	c.HelloIDMu.Unlock()

	// Shuffle the local copy. The PRNG's Shuffle method is internally synchronized,
	// so this call is safe without holding HelloIDMu.
	c.r.Shuffle(len(helloIDs), func(i, j int) {
		helloIDs[i], helloIDs[j] = helloIDs[j], helloIDs[i]
	})
	if workingHelloId != nil {
		helloIDFound := false
		for i, ID := range helloIDs {
			if ID == *workingHelloId {
				helloIDs[i] = helloIDs[0]
				helloIDs[0] = *workingHelloId // push working hello ID first
				helloIDFound = true
				break
			}
		}
		if !helloIDFound {
			helloIDs = append([]ClientHelloID{*workingHelloId}, helloIDs...)
		}
	}

	var lastErr error
	for _, helloID := range helloIDs {
		tcpConn, err := net.DialTimeout(network, addr, c.TcpDialTimeout)
		if err != nil {
			return nil, err // on tcp Dial failure return with error right away
		}

		client, err := UClient(tcpConn, nil, helloID)
		if err != nil {
			tcpConn.Close()
			lastErr = err
			continue // on UClient error keep trying HelloIDs
		}
		client.SetSNI(serverName)
		client.SetDeadline(time.Now().Add(c.TlsHandshakeTimeout))
		err = client.Handshake()
		client.SetDeadline(time.Time{}) // unset timeout
		if err != nil {
			client.Close()
			lastErr = err
			continue // on tls Dial error keep trying HelloIDs
		}

		// Cache the working HelloID for future Dial calls.
		c.HelloIDMu.Lock()
		c.WorkingHelloID = &client.ClientHelloID
		c.HelloIDMu.Unlock()
		return client, nil
	}
	return nil, lastErr
}
