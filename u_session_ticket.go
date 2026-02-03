package tls

import (
	"io"

	utlserrors "github.com/refraction-networking/utls/errors"
)

type ISessionTicketExtension interface {
	TLSExtension

	// If false is returned, utls will invoke `InitializeByUtls()` for the necessary initialization.
	Initializable

	// InitializeByUtls is invoked when IsInitialized() returns false.
	// It initializes the extension using a real and valid TLS 1.2 session.
	InitializeByUtls(session *SessionState, ticket []byte)

	GetSession() *SessionState

	GetTicket() []byte
}

// SessionTicketExtension implements session_ticket (35)
type SessionTicketExtension struct {
	Session     *SessionState
	Ticket      []byte
	Initialized bool
	InitError   error // Stores the reason if initialization failed
}

func (e *SessionTicketExtension) writeToUConn(uc *UConn) error {
	// session states are handled later. At this point tickets aren't
	// being loaded by utls, so don't write anything to the UConn.
	uc.HandshakeState.Hello.TicketSupported = true // This doesn't really matter, this field is only used to add session ticket ext in go tls.
	return nil
}

func (e *SessionTicketExtension) Len() int {
	return 4 + len(e.Ticket)
}

func (e *SessionTicketExtension) Read(b []byte) (int, error) {
	// Session tickets can be large but must fit in TLS extension limits.
	// Extension data length is stored as uint16 (max 65535).
	// Header is 4 bytes (2 type + 2 length), so max ticket is 65531.
	if len(e.Ticket) > 65531 {
		return 0, utlserrors.New("tls: session ticket too long").AtError()
	}

	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}

	extBodyLen := e.Len() - 4

	b[0] = byte(extensionSessionTicket >> 8)
	b[1] = byte(extensionSessionTicket)
	b[2] = byte(extBodyLen >> 8)
	b[3] = byte(extBodyLen)
	if extBodyLen > 0 {
		copy(b[4:], e.Ticket)
	}
	return e.Len(), io.EOF
}

func (e *SessionTicketExtension) IsInitialized() bool {
	return e.Initialized
}

func (e *SessionTicketExtension) InitializeByUtls(session *SessionState, ticket []byte) {
	// Clear any previous error
	e.InitError = nil

	// Validate preconditions - set specific error and return if invalid
	if e.Initialized {
		e.InitError = utlserrors.New("tls: session ticket extension already initialized").AtError()
		return
	}
	if session == nil {
		e.InitError = utlserrors.New("tls: session ticket initialization failed: session is nil").AtError()
		return
	}
	if ticket == nil {
		e.InitError = utlserrors.New("tls: session ticket initialization failed: ticket is nil").AtError()
		return
	}
	if session.version != VersionTLS12 {
		e.InitError = utlserrors.New("tls: session ticket initialization failed: session version mismatch (expected TLS 1.2)").AtError()
		return
	}

	e.Session = session
	e.Ticket = ticket
	e.Initialized = true
}

// GetInitError returns the error that occurred during initialization, or nil if successful.
// Implements InitErrorProvider interface.
func (e *SessionTicketExtension) GetInitError() error {
	return e.InitError
}

func (e *SessionTicketExtension) UnmarshalJSON(_ []byte) error {
	return nil // no-op
}

func (e *SessionTicketExtension) Write(_ []byte) (int, error) {
	// RFC 5077, Section 3.2
	return 0, nil
}

func (e *SessionTicketExtension) GetSession() *SessionState {
	return e.Session
}

func (e *SessionTicketExtension) GetTicket() []byte {
	return e.Ticket
}
