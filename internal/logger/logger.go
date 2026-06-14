// Package logger provides structured logging built on log/slog.
//
// It replaces the standard library log package across GoZone with
// key-value pair logging and configurable log levels.
//
// Usage:
//
//	logger.Info("server started", "addr", ":8080")
//	logger.Warn("rate limit exceeded", "key", "192.168.1.1")
//	logger.Error("zone not found", "zone_id", zoneID, "error", err)
package logger

import (
	"log/slog"
	"os"
)

var defaultLogger *slog.Logger

// osExit is swapped in tests so Fatal can be exercised without terminating the process.
var osExit = os.Exit

func init() {
	defaultLogger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
}

// Init configures the default logger with the given log level string.
//
// Valid levels: debug, info, warn, error.
// Unrecognized values default to info.
func Init(level string) {
	var l slog.Level
	switch level {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	defaultLogger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: l,
	}))
}

// Info logs at level Info with the given message and key-value pairs.
func Info(msg string, args ...any) {
	defaultLogger.Info(msg, args...)
}

// Warn logs at level Warn with the given message and key-value pairs.
func Warn(msg string, args ...any) {
	defaultLogger.Warn(msg, args...)
}

// Error logs at level Error with the given message and key-value pairs.
func Error(msg string, args ...any) {
	defaultLogger.Error(msg, args...)
}

// Debug logs at level Debug with the given message and key-value pairs.
func Debug(msg string, args ...any) {
	defaultLogger.Debug(msg, args...)
}

// Fatal logs at level Error and then calls os.Exit(1).
func Fatal(msg string, args ...any) {
	defaultLogger.Error(msg, args...)
	osExit(1)
}
