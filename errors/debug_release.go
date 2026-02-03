//go:build !debug

package errors

// DebugLoggingEnabled is false in release builds.
// Build with -tags=debug to enable debug logging.
const DebugLoggingEnabled = false
