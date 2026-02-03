// Package errors provides structured error handling and logging for utls.
// This is a standalone error package compatible with xray-core's common/errors.
// Severity values and interfaces match xray-core exactly for interoperability.
package errors

import (
	"context"
	stderrors "errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
)

const trim = len("github.com/refraction-networking/utls/")

// Severity levels for logging.
// Values match xray-core's common/log/log.pb.go exactly:
// Lower value = higher severity (Error=1 is most severe, Debug=4 is least severe)
type Severity int32

const (
	SeverityUnknown Severity = 0
	SeverityError   Severity = 1
	SeverityWarning Severity = 2
	SeverityInfo    Severity = 3
	SeverityDebug   Severity = 4

	// xray-core compatibility aliases
	Severity_Unknown = SeverityUnknown
	Severity_Error   = SeverityError
	Severity_Warning = SeverityWarning
	Severity_Info    = SeverityInfo
	Severity_Debug   = SeverityDebug
)

func (s Severity) String() string {
	switch s {
	case SeverityUnknown:
		return "Unknown"
	case SeverityError:
		return "Error"
	case SeverityWarning:
		return "Warning"
	case SeverityInfo:
		return "Info"
	case SeverityDebug:
		return "Debug"
	default:
		return "Unknown"
	}
}

// globalLogLevel stores the current log level for cheap early-exit checks.
var globalLogLevel atomic.Int32

// logWriter is the output destination for logs (default: stderr)
var logWriter atomic.Value

// logCallback allows external packages to intercept log messages.
// Used by observability_hooks.go to route logs through the hook system.
// Stored as func(Severity, string) or nil.
var logCallback atomic.Value

func init() {
	// Default to Warning level (show warnings and errors)
	globalLogLevel.Store(int32(SeverityWarning))
	logWriter.Store(io.Writer(os.Stderr))
	// logCallback starts as nil (no interception)
}

// SetLogCallback registers a callback that receives all log messages.
// This allows external packages (like observability) to intercept logs
// without creating circular import dependencies.
//
// The callback receives the severity level and the formatted message.
// If the callback is set, logs will ONLY go through the callback
// (not to stderr), so the callback is responsible for final output.
//
// Pass nil to disable the callback and revert to stderr logging.
//
// Thread-safe: uses atomic.Value for lock-free access.
func SetLogCallback(cb func(Severity, string)) {
	if cb == nil {
		logCallback.Store((func(Severity, string))(nil))
	} else {
		logCallback.Store(cb)
	}
}

// SetLogLevel sets the minimum severity level for logging.
func SetLogLevel(s Severity) {
	globalLogLevel.Store(int32(s))
}

// GetLogLevel returns the current log level.
func GetLogLevel() Severity {
	return Severity(globalLogLevel.Load())
}

// SetLogWriter sets the output writer for logs.
func SetLogWriter(w io.Writer) {
	if w == nil {
		w = os.Stderr
	}
	logWriter.Store(w)
}

// ShouldLog returns true if messages at the given severity should be logged.
// Lower severity value = more severe = always logged.
// Example: if level is Info(3), we log Error(1), Warning(2), Info(3), but not Debug(4).
func ShouldLog(severity Severity) bool {
	return severity <= Severity(globalLogLevel.Load())
}

// hasInnerError is the interface for errors with inner errors.
type hasInnerError interface {
	Unwrap() error
}

type hasSeverity interface {
	Severity() Severity
}

// Error is a structured error with context, chaining, and optional stack trace.
type Error struct {
	prefix   []interface{}
	message  []interface{}
	caller   string
	inner    error
	severity Severity
	stack    []uintptr
}

// Error implements error.Error().
func (err *Error) Error() string {
	builder := strings.Builder{}
	for _, prefix := range err.prefix {
		builder.WriteByte('[')
		builder.WriteString(fmt.Sprint(prefix))
		builder.WriteString("] ")
	}

	if len(err.caller) > 0 {
		builder.WriteString(err.caller)
		builder.WriteString(": ")
	}

	builder.WriteString(fmt.Sprint(err.message...))

	if err.inner != nil {
		builder.WriteString(" > ")
		builder.WriteString(err.inner.Error())
	}

	// Append stack trace if present
	if len(err.stack) > 0 {
		builder.WriteString("\nStack trace:\n")
		frames := runtime.CallersFrames(err.stack)
		frameNum := 0
		for {
			frame, more := frames.Next()
			if frame.Function == "" {
				break
			}
			funcName := frame.Function
			if len(funcName) >= trim {
				funcName = funcName[trim:]
			}
			// Extract just filename from full path
			fileName := frame.File
			if idx := strings.LastIndex(fileName, "/"); idx >= 0 {
				fileName = fileName[idx+1:]
			}
			builder.WriteString("  #")
			builder.WriteString(fmt.Sprint(frameNum))
			builder.WriteString(" ")
			builder.WriteString(funcName)
			builder.WriteString(" (")
			builder.WriteString(fileName)
			builder.WriteString(":")
			builder.WriteString(fmt.Sprint(frame.Line))
			builder.WriteString(")\n")
			frameNum++
			if !more {
				break
			}
		}
	}

	return builder.String()
}

// Unwrap implements hasInnerError.Unwrap()
func (err *Error) Unwrap() error {
	if err.inner == nil {
		return nil
	}
	return err.inner
}

// Base sets the inner error.
func (err *Error) Base(e error) *Error {
	err.inner = e
	return err
}

func (err *Error) atSeverity(s Severity) *Error {
	err.severity = s
	return err
}

// Severity returns the error's severity level.
// If inner error has higher severity (lower value), that severity is returned.
func (err *Error) Severity() Severity {
	if err.inner == nil {
		return err.severity
	}
	if s, ok := err.inner.(hasSeverity); ok {
		as := s.Severity()
		// Lower value = more severe, so use inner's severity if it's more severe
		if as < err.severity {
			return as
		}
	}
	return err.severity
}

// AtDebug sets the severity to debug.
func (err *Error) AtDebug() *Error {
	return err.atSeverity(SeverityDebug)
}

// AtInfo sets the severity to info.
func (err *Error) AtInfo() *Error {
	return err.atSeverity(SeverityInfo)
}

// AtWarning sets the severity to warning.
func (err *Error) AtWarning() *Error {
	return err.atSeverity(SeverityWarning)
}

// AtError sets the severity to error.
func (err *Error) AtError() *Error {
	return err.atSeverity(SeverityError)
}

// WithStack captures a full stack trace for detailed debugging.
func (err *Error) WithStack() *Error {
	const maxDepth = 32
	var pcs [maxDepth]uintptr
	n := runtime.Callers(2, pcs[:])
	if n > 0 {
		err.stack = make([]uintptr, n)
		copy(err.stack, pcs[:n])
	}
	return err
}

// Stack returns the captured stack trace, or nil if none was captured.
func (err *Error) Stack() []uintptr {
	return err.stack
}

// String returns the string representation of this error.
func (err *Error) String() string {
	return err.Error()
}

// ExportOptionHolder holds options for error export.
// Compatible with xray-core's ExportOptionHolder.
type ExportOptionHolder struct {
	SessionID uint32
}

// ExportOption is a function that modifies ExportOptionHolder.
// Compatible with xray-core's ExportOption.
type ExportOption func(*ExportOptionHolder)

// New returns a new error object with message formed from given arguments.
func New(msg ...interface{}) *Error {
	pc, _, _, _ := runtime.Caller(1)
	details := runtime.FuncForPC(pc).Name()
	if len(details) >= trim {
		details = details[trim:]
	}
	return &Error{
		message:  msg,
		severity: SeverityInfo,
		caller:   details,
	}
}

// LogDebug logs a debug message.
func LogDebug(ctx context.Context, msg ...interface{}) {
	if !DebugLoggingEnabled {
		return
	}
	if !ShouldLog(SeverityDebug) {
		return
	}
	doLog(ctx, nil, SeverityDebug, msg...)
}

// LogDebugInner logs a debug message with an inner error.
func LogDebugInner(ctx context.Context, inner error, msg ...interface{}) {
	if !DebugLoggingEnabled {
		return
	}
	if !ShouldLog(SeverityDebug) {
		return
	}
	doLog(ctx, inner, SeverityDebug, msg...)
}

// LogInfo logs an info message.
func LogInfo(ctx context.Context, msg ...interface{}) {
	if !ShouldLog(SeverityInfo) {
		return
	}
	doLog(ctx, nil, SeverityInfo, msg...)
}

// LogInfoInner logs an info message with an inner error.
func LogInfoInner(ctx context.Context, inner error, msg ...interface{}) {
	if !ShouldLog(SeverityInfo) {
		return
	}
	doLog(ctx, inner, SeverityInfo, msg...)
}

// LogWarning logs a warning message.
func LogWarning(ctx context.Context, msg ...interface{}) {
	if !ShouldLog(SeverityWarning) {
		return
	}
	doLog(ctx, nil, SeverityWarning, msg...)
}

// LogWarningInner logs a warning message with an inner error.
func LogWarningInner(ctx context.Context, inner error, msg ...interface{}) {
	if !ShouldLog(SeverityWarning) {
		return
	}
	doLog(ctx, inner, SeverityWarning, msg...)
}

// LogError logs an error message.
func LogError(ctx context.Context, msg ...interface{}) {
	if !ShouldLog(SeverityError) {
		return
	}
	doLog(ctx, nil, SeverityError, msg...)
}

// LogErrorInner logs an error message with an inner error.
func LogErrorInner(ctx context.Context, inner error, msg ...interface{}) {
	if !ShouldLog(SeverityError) {
		return
	}
	doLog(ctx, inner, SeverityError, msg...)
}

func doLog(ctx context.Context, inner error, severity Severity, msg ...interface{}) {
	pc, _, _, _ := runtime.Caller(2)
	details := runtime.FuncForPC(pc).Name()
	if len(details) >= trim {
		details = details[trim:]
	}

	// Capture full stack trace for Warning and Error severity levels
	// Lower value = more severe, so Error(1) and Warning(2) get stack traces
	var stack []uintptr
	if severity <= SeverityWarning {
		const maxDepth = 32
		var pcs [maxDepth]uintptr
		n := runtime.Callers(3, pcs[:])
		if n > 0 {
			stack = make([]uintptr, n)
			copy(stack, pcs[:n])
		}
	}

	err := &Error{
		message:  msg,
		severity: severity,
		caller:   details,
		inner:    inner,
		stack:    stack,
	}

	// Extract connection ID from context if available
	if ctx != nil && ctx != context.Background() {
		id := IDFromContext(ctx)
		if id > 0 {
			err.prefix = append(err.prefix, uint32(id))
		}
	}

	// Build the formatted message
	formattedMsg := err.String()

	// Route through callback if registered (observability hook integration)
	if cb := logCallback.Load(); cb != nil {
		if callback, ok := cb.(func(Severity, string)); ok && callback != nil {
			callback(severity, formattedMsg)
			return
		}
	}

	// Fallback to stderr if no callback registered
	w := logWriter.Load().(io.Writer)
	fmt.Fprintf(w, "[%s] %s\n", severity.String(), formattedMsg)
}

// SessionKey is the context key type for session ID.
// Compatible with xray-core's ctx.SessionKey.
type SessionKey int

// ID is the session ID type.
// Compatible with xray-core's ctx.ID.
type ID uint32

const idSessionKey SessionKey = 0

// ContextWithID returns a context with the session ID attached.
// Compatible with xray-core's ctx.ContextWithID.
func ContextWithID(ctx context.Context, id ID) context.Context {
	return context.WithValue(ctx, idSessionKey, id)
}

// IDFromContext extracts the session ID from context.
// Compatible with xray-core's ctx.IDFromContext.
func IDFromContext(ctx context.Context) ID {
	if ctx == nil {
		return 0
	}
	if id, ok := ctx.Value(idSessionKey).(ID); ok {
		return id
	}
	return 0
}

// Legacy aliases for backward compatibility.
// These use the same underlying context key as the xray-compatible functions.

// ContextWithConnID is an alias for ContextWithID for backward compatibility.
func ContextWithConnID(ctx context.Context, id uint32) context.Context {
	return ContextWithID(ctx, ID(id))
}

// ConnIDFromContext is an alias for IDFromContext for backward compatibility.
func ConnIDFromContext(ctx context.Context) uint32 {
	return uint32(IDFromContext(ctx))
}

// Cause returns the root cause of this error by unwrapping the error chain.
// Uses errors.As() for proper Go error unwrapping compatibility.
func Cause(err error) error {
	if err == nil {
		return nil
	}
	for {
		var innerErr hasInnerError
		if stderrors.As(err, &innerErr) {
			unwrapped := innerErr.Unwrap()
			if unwrapped == nil {
				break
			}
			err = unwrapped
		} else {
			break
		}
	}
	return err
}

// GetSeverity returns the actual severity of the error, including inner errors.
// Uses errors.As() for proper Go error unwrapping compatibility.
func GetSeverity(err error) Severity {
	var s hasSeverity
	if stderrors.As(err, &s) {
		return s.Severity()
	}
	return SeverityInfo
}
