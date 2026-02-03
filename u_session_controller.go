package tls

import (
	"context"
	"sync"

	utlserrors "github.com/refraction-networking/utls/errors"
	"github.com/refraction-networking/utls/internal/tls13"
)

// Tracking the state of calling conn.loadSession
type LoadSessionTrackerState int

const NeverCalled LoadSessionTrackerState = 0
const UtlsAboutToCall LoadSessionTrackerState = 1
const CalledByULoadSession LoadSessionTrackerState = 2
const CalledByGoTLS LoadSessionTrackerState = 3

// The state of the session controller
type sessionControllerState int

const NoSession sessionControllerState = 0
const SessionTicketExtInitialized sessionControllerState = 1
const SessionTicketExtAllSet sessionControllerState = 2
const PskExtInitialized sessionControllerState = 3
const PskExtAllSet sessionControllerState = 4

// sessionController is responsible for managing and controlling all session related states. It manages the lifecycle of the session ticket extension and the psk extension, including initialization, removal if the client hello spec doesn't contain any of them, and setting the prepared state to the client hello.
//
// Users should never directly modify the underlying state. Violations will result in undefined behaviors.
//
// Users should never construct sessionController by themselves, use the function `newSessionController` instead.
type sessionController struct {
	// mu protects all mutable fields in sessionController from concurrent access.
	// This prevents race conditions when sessionController methods are called
	// from multiple goroutines (e.g., during concurrent handshakes or when
	// user code accesses session state while handshake is in progress).
	mu sync.Mutex

	// sessionTicketExt logically owns the session ticket extension
	sessionTicketExt ISessionTicketExtension

	// pskExtension logically owns the psk extension
	pskExtension PreSharedKeyExtension

	// uconnRef is a reference to the uconn
	uconnRef *UConn

	// state represents the internal state of the sessionController. Users are advised to modify the state only through designated methods and avoid direct manipulation, as doing so may result in undefined behavior.
	state sessionControllerState

	// loadSessionTracker keeps track of how the conn.loadSession method is being utilized.
	loadSessionTracker LoadSessionTrackerState

	// callingLoadSession is a boolean flag that indicates whether the `conn.loadSession` function is currently being invoked.
	callingLoadSession bool

	// locked is a boolean flag that becomes true once all states are appropriately set. Once `locked` is true, further modifications are disallowed, except for the binders.
	locked bool
}

// newSessionController constructs a new SessionController
func newSessionController(uconn *UConn) *sessionController {
	return &sessionController{
		uconnRef:           uconn,
		sessionTicketExt:   nil,
		pskExtension:       nil,
		state:              NoSession,
		locked:             false,
		callingLoadSession: false,
		loadSessionTracker: NeverCalled,
	}
}

func (s *sessionController) isSessionLocked() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.locked
}

type shouldLoadSessionResult int

const shouldReturn shouldLoadSessionResult = 0
const shouldSetTicket shouldLoadSessionResult = 1
const shouldSetPsk shouldLoadSessionResult = 2
const shouldLoad shouldLoadSessionResult = 3

// shouldLoadSession determines the appropriate action to take when it is time to load the session for the clientHello.
// There are several possible scenarios:
//   - If a session ticket is already initialized, typically via the `initSessionTicketExt()` function, the ticket should be set in the client hello.
//   - If a pre-shared key (PSK) is already initialized, typically via the `overridePskExt()` function, the PSK should be set in the client hello.
//   - If both the `sessionTicketExt` and `pskExtension` are nil, which might occur if the client hello spec does not include them, we should skip the loadSession().
//   - In all other cases, the function proceeds to load the session.
//
// Thread-safe: Protected by mu.
func (s *sessionController) shouldLoadSession() shouldLoadSessionResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessionTicketExt == nil && s.pskExtension == nil || s.uconnRef.clientHelloBuildStatus != NotBuilt {
		// No need to load session since we don't have the related extensions.
		return shouldReturn
	}
	if s.state == SessionTicketExtInitialized {
		return shouldSetTicket
	}
	if s.state == PskExtInitialized {
		return shouldSetPsk
	}
	return shouldLoad
}

// utlsAboutToLoadSession updates the loadSessionTracker to `UtlsAboutToCall` to signal the initiation of a session loading operation,
// provided that the preconditions are met.
//
// Thread-safe: Protected by mu.
func (s *sessionController) utlsAboutToLoadSession() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !(s.state == NoSession && !s.locked) {
		return utlserrors.New("tls: aboutToLoadSession failed: must only load session when the session of the client hello is not locked and when there's currently no session").AtError()
	}
	utlserrors.LogDebug(context.Background(), "session controller: about to load session")
	s.loadSessionTracker = UtlsAboutToCall
	return nil
}

// assertHelloNotBuilt checks if ClientHello has not been built yet.
// Internal helper - caller must hold s.mu lock.
func (s *sessionController) assertHelloNotBuilt(caller string) error {
	if s.uconnRef.clientHelloBuildStatus != NotBuilt {
		return utlserrors.New("tls: ", caller, " failed: we can't modify the session after the clientHello is built").AtError()
	}
	return nil
}

// assertControllerState verifies the controller is in one of the desired states.
// Internal helper - caller must hold s.mu lock.
func (s *sessionController) assertControllerState(caller string, desired sessionControllerState, moreDesiredStates ...sessionControllerState) error {
	if s.state != desired && !anyTrue(moreDesiredStates, func(_ int, state *sessionControllerState) bool {
		return s.state == *state
	}) {
		return utlserrors.New("tls: ", caller, " failed: undesired controller state ", s.state).AtError()
	}
	return nil
}

// assertNotLocked verifies the session is not yet locked.
// Internal helper - caller must hold s.mu lock.
func (s *sessionController) assertNotLocked(caller string) error {
	if s.locked {
		return utlserrors.New("tls: ", caller, " failed: you must not modify the session after it's locked").AtError()
	}
	return nil
}

// assertCanSkip checks if session resumption can be skipped.
// Internal helper - caller must hold s.mu lock.
func (s *sessionController) assertCanSkip(caller, extensionName string) error {
	if !s.uconnRef.skipResumptionOnNilExtension {
		return utlserrors.New("tls: ", caller, " failed: session resumption is enabled, but there is no ", extensionName, " in the ClientHelloSpec; Please consider provide one in the ClientHelloSpec; If this is intentional, you may consider disable resumption by setting Config.SessionTicketsDisabled to true, or set Config.PreferSkipResumptionOnNilExtension to true to suppress this exception").AtError()
	}
	return nil
}

// finalCheck performs a comprehensive check on the updated state to ensure the correctness of the changes.
// If the checks pass successfully, the sessionController's state will be locked.
// Any failure in passing the tests indicates incorrect implementations in the utls.
// Refer to the documentation for the `locked` field for more detailed information.
//
// Thread-safe: Protected by mu.
func (s *sessionController) finalCheck() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.assertControllerState("SessionController.finalCheck", PskExtAllSet, SessionTicketExtAllSet, NoSession); err != nil {
		return err
	}
	s.locked = true
	utlserrors.LogDebug(context.Background(), "session controller: final check passed, state locked, finalState=", s.state)
	return nil
}

// errOnNil returns an error if any of the parameters is nil.
func errOnNil(caller string, params ...any) error {
	for i, p := range params {
		if p == nil {
			return utlserrors.New("tls: ", caller, " failed: the [", i, "] parameter is nil").AtError()
		}
	}
	return nil
}

// initializationGuardWithErr is an error-returning version of initializationGuard.
func initializationGuardWithErr[E Initializable, I func(E)](extension E, initializer I) error {
	if extension.IsInitialized() {
		return utlserrors.New("tls: initialization failed: the extension is already initialized").AtError()
	}
	initializer(extension)
	if !extension.IsInitialized() {
		// Check if the extension provides a specific error reason
		if errProvider, ok := any(extension).(InitErrorProvider); ok {
			if initErr := errProvider.GetInitError(); initErr != nil {
				return utlserrors.New("tls: initialization failed").Base(initErr).AtError()
			}
		}
		return utlserrors.New("tls: initialization failed: the extension is not initialized after initialization").AtError()
	}
	return nil
}

// initSessionTicketExt initializes the ticket and sets the state to `TicketInitialized`.
//
// Thread-safe: Protected by mu.
func (s *sessionController) initSessionTicketExt(session *SessionState, ticket []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.assertNotLocked("initSessionTicketExt"); err != nil {
		return err
	}
	if err := s.assertHelloNotBuilt("initSessionTicketExt"); err != nil {
		return err
	}
	if err := s.assertControllerState("initSessionTicketExt", NoSession); err != nil {
		return err
	}
	if err := errOnNil("initSessionTicketExt", session, ticket); err != nil {
		return err
	}
	if s.sessionTicketExt == nil {
		if err := s.assertCanSkip("initSessionTicketExt", "session ticket extension"); err != nil {
			return err
		}
		return nil
	}
	if err := initializationGuardWithErr(s.sessionTicketExt, func(e ISessionTicketExtension) {
		s.sessionTicketExt.InitializeByUtls(session, ticket)
	}); err != nil {
		return err
	}
	s.state = SessionTicketExtInitialized
	utlserrors.LogDebug(context.Background(), "session controller: session ticket extension initialized, ticketSize=", len(ticket))
	return nil
}

// initPSK initializes the PSK extension using a valid session. The PSK extension
// should not be initialized previously, and the parameters must not be nil.
//
// Thread-safe: Protected by mu.
func (s *sessionController) initPskExt(session *SessionState, earlySecret *tls13.EarlySecret, binderKey []byte, pskIdentities []pskIdentity) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.assertNotLocked("initPskExt"); err != nil {
		return err
	}
	if err := s.assertHelloNotBuilt("initPskExt"); err != nil {
		return err
	}
	if err := s.assertControllerState("initPskExt", NoSession); err != nil {
		return err
	}
	if err := errOnNil("initPskExt", session, earlySecret, pskIdentities); err != nil {
		return err
	}
	if s.pskExtension == nil {
		if err := s.assertCanSkip("initPskExt", "pre-shared key extension"); err != nil {
			return err
		}
		return nil
	}
	if err := initializationGuardWithErr(s.pskExtension, func(e PreSharedKeyExtension) {
		publicPskIdentities := mapSlice(pskIdentities, func(private pskIdentity) PskIdentity {
			return PskIdentity{
				Label:               private.label,
				ObfuscatedTicketAge: private.obfuscatedTicketAge,
			}
		})
		e.InitializeByUtls(session, earlySecret.Secret(), binderKey, publicPskIdentities)
	}); err != nil {
		return err
	}
	s.state = PskExtInitialized
	utlserrors.LogDebug(context.Background(), "session controller: PSK extension initialized, identities=", len(pskIdentities))
	return nil
}

// setSessionTicketToUConn write the ticket states from the session ticket extension to the client hello and handshake state.
//
// Thread-safe: Protected by mu.
func (s *sessionController) setSessionTicketToUConn() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !(s.sessionTicketExt != nil && s.state == SessionTicketExtInitialized) {
		return utlserrors.New("tls: setSessionTicketExt failed: invalid state").AtError()
	}
	s.uconnRef.HandshakeState.Session = s.sessionTicketExt.GetSession()
	s.uconnRef.HandshakeState.Hello.SessionTicket = s.sessionTicketExt.GetTicket()
	s.state = SessionTicketExtAllSet
	utlserrors.LogDebug(context.Background(), "session controller: session ticket set to UConn")
	return nil
}

// setPskToUConn sets the psk to the handshake state and client hello.
//
// Thread-safe: Protected by mu.
func (s *sessionController) setPskToUConn() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !(s.pskExtension != nil && (s.state == PskExtInitialized || s.state == PskExtAllSet)) {
		return utlserrors.New("tls: setPskToUConn failed: invalid state").AtError()
	}
	pskCommon := s.pskExtension.GetPreSharedKeyCommon()
	if s.state == PskExtInitialized {
		s.uconnRef.HandshakeState.State13.EarlySecret = pskCommon.EarlySecret
		s.uconnRef.HandshakeState.Session = pskCommon.Session
		s.uconnRef.HandshakeState.Hello.PskIdentities = pskCommon.Identities
		s.uconnRef.HandshakeState.Hello.PskBinders = pskCommon.Binders
		utlserrors.LogDebug(context.Background(), "session controller: PSK initialized, identities=", len(pskCommon.Identities))
	} else if s.state == PskExtAllSet {
		bindersMatch := s.uconnRef.HandshakeState.Session == pskCommon.Session &&
			sliceEq(s.uconnRef.HandshakeState.State13.EarlySecret, pskCommon.EarlySecret) &&
			allTrue(s.uconnRef.HandshakeState.Hello.PskIdentities, func(i int, psk *PskIdentity) bool {
				return pskCommon.Identities[i].ObfuscatedTicketAge == psk.ObfuscatedTicketAge && sliceEq(pskCommon.Identities[i].Label, psk.Label)
			})
		if !bindersMatch {
			return utlserrors.New("tls: setPskToUConn failed: only binders are allowed to change on state PskAllSet").AtError()
		}
		utlserrors.LogDebug(context.Background(), "session controller: PSK binders updated")
	}
	s.uconnRef.HandshakeState.State13.BinderKey = pskCommon.BinderKey
	s.state = PskExtAllSet
	return nil
}

// shouldUpdateBinders determines whether binders should be updated based on the presence of an initialized psk extension.
// This function returns true if an initialized psk extension exists. Binders are allowed to be updated when the state is `PskAllSet`,
// as the `BuildHandshakeState` function can be called multiple times in this case. However, it's important to note that
// the session state, apart from binders, should not be altered more than once.
//
// Thread-safe: Protected by mu.
func (s *sessionController) shouldUpdateBinders() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.shouldUpdateBindersLocked()
}

// shouldUpdateBindersLocked is the internal version that requires caller to hold the lock.
// Internal helper - caller must hold s.mu lock.
func (s *sessionController) shouldUpdateBindersLocked() bool {
	if s.pskExtension == nil {
		return false
	}
	return (s.state == PskExtInitialized || s.state == PskExtAllSet)
}

// updateBinders updates the PSK binders in the ClientHello.
//
// Thread-safe: Protected by mu.
func (s *sessionController) updateBinders() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.shouldUpdateBindersLocked() {
		return utlserrors.New("tls: updateBinders failed: shouldn't update binders").AtError()
	}
	utlserrors.LogDebug(context.Background(), "session controller: updating PSK binders")
	return s.pskExtension.PatchBuiltHello(s.uconnRef.HandshakeState.Hello)
}

// overrideExtensionLocked is the internal implementation of extension override.
// Internal helper - caller must hold s.mu lock.
func (s *sessionController) overrideExtensionLocked(extension Initializable, override func(), initializedState sessionControllerState) error {
	if err := errOnNil("overrideExtension", extension); err != nil {
		return err
	}
	if err := s.assertNotLocked("overrideExtension"); err != nil {
		return err
	}
	if err := s.assertControllerState("overrideExtension", NoSession); err != nil {
		return err
	}
	override()
	if extension.IsInitialized() {
		s.state = initializedState
	}
	return nil
}

// overridePskExt allows the user of utls to customize the psk extension.
//
// Thread-safe: Protected by mu.
func (s *sessionController) overridePskExt(pskExt PreSharedKeyExtension) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.overrideExtensionLocked(pskExt, func() { s.pskExtension = pskExt }, PskExtInitialized)
}

// overrideSessionTicketExt allows the user of utls to customize the session ticket extension.
//
// Thread-safe: Protected by mu.
func (s *sessionController) overrideSessionTicketExt(sessionTicketExt ISessionTicketExtension) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.overrideExtensionLocked(sessionTicketExt, func() { s.sessionTicketExt = sessionTicketExt }, SessionTicketExtInitialized)
}

// syncSessionExts synchronizes the sessionController with the session-related
// extensions from the extension list after applying client hello specs.
//
//   - If the extension list is missing the session ticket extension or PSK
//     extension, owned extensions are dropped and states are reset.
//   - If the user provides a session ticket extension or PSK extension, the
//     corresponding extension from the extension list will be replaced.
//   - If the user doesn't provide session-related extensions, the extensions
//     from the extension list will be utilized.
//
// This function ensures that there is only one session ticket extension or PSK
// extension, and that the PSK extension is the last extension in the extension
// list.
//
// Thread-safe: Protected by mu.
func (s *sessionController) syncSessionExts() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	utlserrors.LogDebug(context.Background(), "session controller: syncing session extensions")
	if s.uconnRef.clientHelloBuildStatus != NotBuilt {
		return utlserrors.New("tls: checkSessionExts failed: we can't modify the session after the clientHello is built").AtError()
	}
	if err := s.assertNotLocked("checkSessionExts"); err != nil {
		return err
	}
	if err := s.assertHelloNotBuilt("checkSessionExts"); err != nil {
		return err
	}
	if err := s.assertControllerState("checkSessionExts", NoSession, SessionTicketExtInitialized, PskExtInitialized); err != nil {
		return err
	}
	numSessionExt := 0
	hasPskExt := false
	for i, e := range s.uconnRef.Extensions {
		switch ext := e.(type) {
		case ISessionTicketExtension:
			if numSessionExt != 0 {
				return utlserrors.New("tls: checkSessionExts failed: multiple ISessionTicketExtensions in the extension list").AtError()
			}
			if s.sessionTicketExt == nil {
				// If there isn't a user-provided session ticket extension, use the one from the spec
				s.sessionTicketExt = ext
			} else {
				// Otherwise, replace the one in the extension list with the user-provided one
				s.uconnRef.Extensions[i] = s.sessionTicketExt
			}
			numSessionExt += 1
		case PreSharedKeyExtension:
			if i != len(s.uconnRef.Extensions)-1 {
				return utlserrors.New("tls: checkSessionExts failed: PreSharedKeyExtension must be the last extension").AtError()
			}
			if s.pskExtension == nil {
				// If there isn't a user-provided psk extension, use the one from the spec
				s.pskExtension = ext
			} else {
				// Otherwise, replace the one in the extension list with the user-provided one
				s.uconnRef.Extensions[i] = s.pskExtension
			}
			s.pskExtension.SetOmitEmptyPsk(s.uconnRef.config.OmitEmptyPsk)
			hasPskExt = true
		}
	}
	if numSessionExt == 0 {
		if s.state == SessionTicketExtInitialized {
			return utlserrors.New("tls: checkSessionExts failed: the user provided a session ticket, but the specification doesn't contain one").AtError()
		}
		s.sessionTicketExt = nil
		s.uconnRef.HandshakeState.Session = nil
		s.uconnRef.HandshakeState.Hello.SessionTicket = nil
		utlserrors.LogDebug(context.Background(), "session controller: no session ticket extension in spec")
	}
	if !hasPskExt {
		if s.state == PskExtInitialized {
			return utlserrors.New("tls: checkSessionExts failed: the user provided a psk, but the specification doesn't contain one").AtError()
		}
		s.pskExtension = nil
		s.uconnRef.HandshakeState.State13.BinderKey = nil
		s.uconnRef.HandshakeState.State13.EarlySecret = nil
		s.uconnRef.HandshakeState.Session = nil
		s.uconnRef.HandshakeState.Hello.PskIdentities = nil
		utlserrors.LogDebug(context.Background(), "session controller: no PSK extension in spec")
	}
	return nil
}

// onEnterLoadSessionCheck is intended to be invoked upon entering the `conn.loadSession` function.
// It is designed to ensure the correctness of the utls implementation.
//
// Thread-safe: Protected by mu.
func (s *sessionController) onEnterLoadSessionCheck() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.locked {
		return utlserrors.New("tls: LoadSessionCoordinator.onEnterLoadSessionCheck failed: session is set and locked, no call to loadSession is allowed").AtError()
	}
	switch s.loadSessionTracker {
	case UtlsAboutToCall, NeverCalled:
		s.callingLoadSession = true
		utlserrors.LogDebug(context.Background(), "session controller: entering loadSession, tracker=", s.loadSessionTracker)
		return nil
	case CalledByULoadSession, CalledByGoTLS:
		return utlserrors.New("tls: LoadSessionCoordinator.onEnterLoadSessionCheck failed: you must not call loadSession() twice").AtError()
	default:
		return utlserrors.New("tls: LoadSessionCoordinator.onEnterLoadSessionCheck failed: unimplemented state").AtError()
	}
}

// onLoadSessionReturn is intended to be invoked upon returning from the `conn.loadSession` function.
// It serves as a validation step for the correctness of the underlying utls implementation.
//
// Thread-safe: Protected by mu.
func (s *sessionController) onLoadSessionReturn() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.callingLoadSession {
		return utlserrors.New("tls: LoadSessionCoordinator.onLoadSessionReturn failed: it's not loading sessions, perhaps this function is not being called by loadSession").AtError()
	}
	switch s.loadSessionTracker {
	case NeverCalled:
		s.loadSessionTracker = CalledByGoTLS
		utlserrors.LogDebug(context.Background(), "session controller: loadSession returned, calledBy=GoTLS")
	case UtlsAboutToCall:
		s.loadSessionTracker = CalledByULoadSession
		utlserrors.LogDebug(context.Background(), "session controller: loadSession returned, calledBy=ULoadSession")
	default:
		return utlserrors.New("tls: LoadSessionCoordinator.onLoadSessionReturn failed: unimplemented state").AtError()
	}
	s.callingLoadSession = false
	return nil
}

// shouldLoadSessionWriteBinders checks if `conn.loadSession` should proceed to write binders and marshal the client hello.
//
// Thread-safe: Protected by mu.
func (s *sessionController) shouldLoadSessionWriteBinders() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.callingLoadSession {
		return false, utlserrors.New("tls: shouldWriteBinders failed: LoadSessionCoordinator isn't loading sessions, perhaps this function is not being called by loadSession").AtError()
	}

	switch s.loadSessionTracker {
	case NeverCalled:
		utlserrors.LogDebug(context.Background(), "session controller: should write binders (NeverCalled)")
		return true, nil
	case UtlsAboutToCall:
		utlserrors.LogDebug(context.Background(), "session controller: should not write binders (UtlsAboutToCall)")
		return false, nil
	default:
		return false, utlserrors.New("tls: shouldWriteBinders failed: unimplemented state").AtError()
	}
}
