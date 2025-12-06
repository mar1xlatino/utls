package memcontrol

import (
	"fmt"
	"log"
	"os"
	"sync/atomic"
)

// LogLevel represents logging verbosity.
type LogLevel int32

const (
	LogLevelOff   LogLevel = 0 // No logging
	LogLevelError LogLevel = 1 // Errors only
	LogLevelWarn  LogLevel = 2 // Warnings and errors
	LogLevelInfo  LogLevel = 3 // Info, warnings, errors
	LogLevelDebug LogLevel = 4 // All messages including debug
)

// Logger handles memcontrol logging with configurable levels and custom handlers.
type Logger struct {
	level   atomic.Int32
	handler atomic.Pointer[func(level LogLevel, msg string)]
}

var globalLogger = &Logger{}

func init() {
	// Default to warnings only, can be overridden by env or SetLogLevel
	level := LogLevelWarn
	if os.Getenv("UTLS_MEMCONTROL_DEBUG") == "1" {
		level = LogLevelDebug
	} else if os.Getenv("UTLS_MEMCONTROL_QUIET") == "1" {
		level = LogLevelOff
	}
	globalLogger.level.Store(int32(level))
}

// SetLogLevel sets the global logging level.
func SetLogLevel(level LogLevel) {
	globalLogger.level.Store(int32(level))
}

// GetLogLevel returns the current logging level.
func GetLogLevel() LogLevel {
	return LogLevel(globalLogger.level.Load())
}

// SetLogHandler sets a custom log handler. If nil, uses default log.Printf.
// The handler receives the log level and formatted message.
//
// Example with zerolog:
//
//	memcontrol.SetLogHandler(func(level memcontrol.LogLevel, msg string) {
//	    switch level {
//	    case memcontrol.LogLevelError:
//	        log.Error().Msg(msg)
//	    case memcontrol.LogLevelWarn:
//	        log.Warn().Msg(msg)
//	    case memcontrol.LogLevelInfo:
//	        log.Info().Msg(msg)
//	    case memcontrol.LogLevelDebug:
//	        log.Debug().Msg(msg)
//	    }
//	})
func SetLogHandler(handler func(level LogLevel, msg string)) {
	if handler == nil {
		globalLogger.handler.Store(nil)
		return
	}
	globalLogger.handler.Store(&handler)
}

func logf(level LogLevel, format string, args ...any) {
	if LogLevel(globalLogger.level.Load()) < level {
		return
	}

	// Format message
	var msg string
	if len(args) == 0 {
		msg = format
	} else {
		msg = sprintf(format, args...)
	}

	// Use custom handler if set
	if h := globalLogger.handler.Load(); h != nil {
		(*h)(level, msg)
		return
	}

	// Default to standard log with level prefix
	var prefix string
	switch level {
	case LogLevelError:
		prefix = "[ERROR]"
	case LogLevelWarn:
		prefix = "[WARN]"
	case LogLevelInfo:
		prefix = "[INFO]"
	case LogLevelDebug:
		prefix = "[DEBUG]"
	}
	log.Printf("%s [memcontrol] %s", prefix, msg)
}

// sprintf formats a string (logging is not performance critical)
func sprintf(format string, args ...any) string {
	return fmt.Sprintf(format, args...)
}

// Logging convenience functions
func logError(format string, args ...any) { logf(LogLevelError, format, args...) }
func logWarn(format string, args ...any)  { logf(LogLevelWarn, format, args...) }
func logInfo(format string, args ...any)  { logf(LogLevelInfo, format, args...) }
func logDebug(format string, args ...any) { logf(LogLevelDebug, format, args...) }
