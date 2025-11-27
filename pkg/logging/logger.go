package logging

import (
	"fmt"
	"os"
	"time"
)

// Logger provides structured logging with color-coded severity
type Logger struct {
	file *os.File
}

// Color codes for terminal output
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorGreen  = "\033[32m"
	colorBlue   = "\033[34m"
)

// NewLogger creates a new logger instance
func NewLogger(filePath string) *Logger {
	logger := &Logger{}

	if filePath != "" {
		file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open log file: %v\n", err)
		} else {
			logger.file = file
		}
	}

	return logger
}

// Close closes the log file if it's open
func (l *Logger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// Info logs an info message
func (l *Logger) Info(format string, args ...interface{}) {
	l.log("INFO", colorBlue, format, args...)
}

// Warn logs a warning message
func (l *Logger) Warn(format string, args ...interface{}) {
	l.log("WARN", colorYellow, format, args...)
}

// Error logs an error message
func (l *Logger) Error(format string, args ...interface{}) {
	l.log("ERROR", colorRed, format, args...)
}

// Debug logs a debug message
func (l *Logger) Debug(format string, args ...interface{}) {
	l.log("DEBUG", colorGreen, format, args...)
}

// Block logs a blocked request
func (l *Logger) Block(format string, args ...interface{}) {
	l.log("BLOCK", colorRed, format, args...)
}

// log is the internal logging function
func (l *Logger) log(level, color, format string, args ...interface{}) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	message := fmt.Sprintf(format, args...)

	// Terminal output with color
	coloredOutput := fmt.Sprintf("%s[%s] %s%s %s\n", color, timestamp, level, colorReset, message)
	fmt.Fprint(os.Stdout, coloredOutput)

	// File output (plain text)
	if l.file != nil {
		plainOutput := fmt.Sprintf("[%s] %s %s\n", timestamp, level, message)
		l.file.WriteString(plainOutput)
	}
}
