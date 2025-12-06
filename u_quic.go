// Copyright 2023 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// QUIC Transport Support for uTLS
//
// This file provides UQUICConn, a QUIC-TLS integration type that allows using
// uTLS fingerprinting capabilities with QUIC transport protocols (RFC 9001).
//
// CONCURRENCY WARNING
//
// UQUICConn is NOT safe for concurrent use. All method calls on a single
// UQUICConn instance MUST be serialized by the caller. Concurrent access
// from multiple goroutines will result in undefined behavior, data races,
// and potential security vulnerabilities.
//
// The following methods are NOT concurrent-safe:
//   - Start: Initiates handshake, spawns internal goroutine
//   - NextEvent: Reads and consumes events from internal queue
//   - HandleData: Processes incoming handshake data
//   - SetTransportParameters: Modifies connection state
//   - SendSessionTicket: Modifies session state
//   - ApplyPreset: Modifies ClientHello configuration
//   - Close: Terminates connection and waits for goroutines
//
// Only ConnectionState may be called concurrently after the handshake completes.
//
// Recommended Usage Patterns:
//
// Pattern 1 - Single Goroutine (Recommended):
//
//	func handleQUIC(conn *UQUICConn) {
//	    // All operations on conn happen in this single goroutine
//	    conn.Start(ctx)
//	    for {
//	        event := conn.NextEvent()
//	        // ... process event
//	    }
//	}
//
// Pattern 2 - External Synchronization:
//
//	var mu sync.Mutex
//	func sendData(conn *UQUICConn, data []byte) {
//	    mu.Lock()
//	    defer mu.Unlock()
//	    conn.HandleData(level, data)
//	}
//
// For concurrent access detection during development, run your tests with:
//
//	go test -race ./...
//
// The Go race detector will identify concurrent access violations.

package tls

import (
	"context"
	"errors"
	"fmt"
)

// UQUICConn represents a connection which uses a QUIC implementation as the
// underlying transport as described in RFC 9001.
//
// WARNING: NOT CONCURRENT-SAFE
//
// Methods of UQUICConn are NOT safe for concurrent use from multiple goroutines.
// The caller MUST ensure that only one goroutine accesses a UQUICConn at a time,
// or use external synchronization (e.g., sync.Mutex).
//
// Concurrent access will cause data races and undefined behavior. Use the Go
// race detector (-race flag) during development to catch violations.
//
// See package-level documentation for safe usage patterns and the complete list
// of non-concurrent-safe methods.
type UQUICConn struct {
	conn *UConn

	sessionTicketSent bool
}

// UQUICClient returns a new TLS client side connection using QUICTransport as the
// underlying transport. The config cannot be nil.
//
// The config's MinVersion must be at least TLS 1.3.
//
// Unlike UClient, this function does not require a net.Conn because QUIC
// manages the underlying transport internally. The nil connection is valid
// for QUIC usage only.
func UQUICClient(config *QUICConfig, clientHelloID ClientHelloID) *UQUICConn {
	return newUQUICConn(uClient(nil, config.TLSConfig, clientHelloID))
}

func newUQUICConn(uconn *UConn) *UQUICConn {
	uconn.quic = &quicState{
		signalc:  make(chan struct{}),
		blockedc: make(chan struct{}),
	}
	uconn.quic.events = uconn.quic.eventArr[:0]
	return &UQUICConn{
		conn: uconn,
	}
}

// Start starts the client or server handshake protocol.
// It may produce connection events, which may be read with NextEvent.
//
// Start must be called at most once.
func (q *UQUICConn) Start(ctx context.Context) error {
	if q.conn.quic.started {
		return quicError(errors.New("tls: Start called more than once"))
	}
	q.conn.quic.started = true
	if q.conn.config.MinVersion < VersionTLS13 {
		return quicError(errors.New("tls: Config MinVersion must be at least TLS 1.3"))
	}
	go q.conn.HandshakeContext(ctx)
	if _, ok := <-q.conn.quic.blockedc; !ok {
		return q.conn.handshakeErr
	}
	return nil
}

func (q *UQUICConn) ApplyPreset(p *ClientHelloSpec) error {
	return q.conn.ApplyPreset(p)
}

// NextEvent returns the next event occurring on the connection.
// It returns an event with a Kind of QUICNoEvent when no events are available.
func (q *UQUICConn) NextEvent() QUICEvent {
	qs := q.conn.quic
	if last := qs.nextEvent - 1; last >= 0 && len(qs.events[last].Data) > 0 {
		// Write over some of the previous event's data,
		// to catch callers erroniously retaining it.
		qs.events[last].Data[0] = 0
	}
	// Handle drain synchronization for session resumption events (QUICResumeSession)
	// This must be checked before returning QUICNoEvent to ensure proper synchronization
	// with quicResumeSession() which sets waitingForDrain = true
	if qs.nextEvent >= len(qs.events) && qs.waitingForDrain.Load() {
		qs.waitingForDrain.Store(false)
		<-qs.signalc
		<-qs.blockedc
	}
	if qs.nextEvent >= len(qs.events) {
		qs.events = qs.events[:0]
		qs.nextEvent = 0
		return QUICEvent{Kind: QUICNoEvent}
	}
	e := qs.events[qs.nextEvent]
	qs.events[qs.nextEvent] = QUICEvent{} // zero out references to data
	qs.nextEvent++
	return e
}

// Close closes the connection and stops any in-progress handshake.
func (q *UQUICConn) Close() error {
	if q.conn.quic.cancel == nil {
		return nil // never started
	}
	q.conn.quic.cancel()
	for range q.conn.quic.blockedc {
		// Wait for the handshake goroutine to return.
	}
	return q.conn.handshakeErr
}

// HandleData handles handshake bytes received from the peer.
// It may produce connection events, which may be read with NextEvent.
func (q *UQUICConn) HandleData(level QUICEncryptionLevel, data []byte) error {
	c := q.conn
	if c.in.level != level {
		return quicError(c.in.setErrorLocked(errors.New("tls: handshake data received at wrong level")))
	}
	c.quic.readbuf = data
	<-c.quic.signalc
	_, ok := <-c.quic.blockedc
	if ok {
		// The handshake goroutine is waiting for more data.
		return nil
	}
	// The handshake goroutine has exited.
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()
	c.hand.Write(c.quic.readbuf)
	c.quic.readbuf = nil
	for q.conn.hand.Len() >= 4 && q.conn.handshakeErr == nil {
		b := q.conn.hand.Bytes()
		n := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
		if n > maxHandshake {
			q.conn.handshakeErr = fmt.Errorf("tls: handshake message of length %d bytes exceeds maximum of %d bytes", n, maxHandshake)
			break
		}
		if len(b) < 4+n {
			return nil
		}
		if err := q.conn.handlePostHandshakeMessage(); err != nil {
			q.conn.handshakeErr = err
		}
	}
	if q.conn.handshakeErr != nil {
		return quicError(q.conn.handshakeErr)
	}
	return nil
}

// SendSessionTicket sends a session ticket to the client.
// It produces connection events, which may be read with NextEvent.
// Currently, it can only be called once.
func (q *UQUICConn) SendSessionTicket(opts QUICSessionTicketOptions) error {
	c := q.conn
	if !c.isHandshakeComplete.Load() {
		return quicError(errors.New("tls: SendSessionTicket called before handshake completed"))
	}
	if c.isClient {
		return quicError(errors.New("tls: SendSessionTicket called on the client"))
	}
	if q.sessionTicketSent {
		return quicError(errors.New("tls: SendSessionTicket called multiple times"))
	}
	q.sessionTicketSent = true
	return quicError(c.sendSessionTicket(opts.EarlyData, opts.Extra))
}

// ConnectionState returns basic TLS details about the connection.
func (q *UQUICConn) ConnectionState() ConnectionState {
	return q.conn.ConnectionState()
}

// SetTransportParameters sets the transport parameters to send to the peer.
//
// Server connections may delay setting the transport parameters until after
// receiving the client's transport parameters. See QUICTransportParametersRequired.
func (q *UQUICConn) SetTransportParameters(params []byte) {
	if params == nil {
		params = []byte{}
	}
	q.conn.quic.transportParams = params // this won't be used for building ClientHello when using a preset

	// // instead, we set the transport parameters hold by the ClientHello
	// for _, ext := range q.conn.Extensions {
	// 	if qtp, ok := ext.(*QUICTransportParametersExtension); ok {
	// 		qtp.TransportParametersExtData = params
	// 	}
	// }

	if q.conn.quic.started {
		<-q.conn.quic.signalc
		<-q.conn.quic.blockedc
	}
}

func (uc *UConn) QUICSetReadSecret(level QUICEncryptionLevel, suite uint16, secret []byte) {
	uc.quic.events = append(uc.quic.events, QUICEvent{
		Kind:  QUICSetReadSecret,
		Level: level,
		Suite: suite,
		Data:  secret,
	})
}

func (uc *UConn) QUICSetWriteSecret(level QUICEncryptionLevel, suite uint16, secret []byte) {
	uc.quic.events = append(uc.quic.events, QUICEvent{
		Kind:  QUICSetWriteSecret,
		Level: level,
		Suite: suite,
		Data:  secret,
	})
}

func (uc *UConn) QUICGetTransportParameters() ([]byte, error) {
	if uc.quic.transportParams == nil {
		uc.quic.events = append(uc.quic.events, QUICEvent{
			Kind: QUICTransportParametersRequired,
		})
	}
	for uc.quic.transportParams == nil {
		if err := uc.quicWaitForSignal(); err != nil {
			return nil, err
		}
	}
	return uc.quic.transportParams, nil
}
