package logging

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// StructuredEvent represents a structured WAF event for SIEM/data analysis
type StructuredEvent struct {
	Timestamp       time.Time              `json:"timestamp"`
	EventID         string                 `json:"event_id"`
	EventType       string                 `json:"event_type"` // "request", "blocked", "anomaly", "analysis"
	Severity        string                 `json:"severity"`   // "low", "medium", "high", "critical"
	SourceIP        string                 `json:"source_ip"`
	DestinationIP   string                 `json:"destination_ip"`
	Method          string                 `json:"method"`
	URL             string                 `json:"url"`
	UserAgent       string                 `json:"user_agent"`
	ContentType     string                 `json:"content_type"`
	RequestSize     int64                  `json:"request_size"`
	ResponseSize    int64                  `json:"response_size"`
	StatusCode      int                    `json:"status_code"`
	RuleID          string                 `json:"rule_id,omitempty"`
	RuleName        string                 `json:"rule_name,omitempty"`
	RuleAction      string                 `json:"rule_action,omitempty"` // "block", "allow", "log"
	Blocked         bool                   `json:"blocked"`
	Reason          string                 `json:"reason,omitempty"`
	Payload         string                 `json:"payload,omitempty"`
	PayloadEntropy  float64                `json:"payload_entropy,omitempty"`
	Headers         map[string]string      `json:"headers,omitempty"`
	QueryParams     map[string]string      `json:"query_params,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
	ResponseTime    int64                  `json:"response_time_ms"`
}

// StructuredLogger handles structured logging for SIEM integration
type StructuredLogger struct {
	mu           sync.Mutex
	jsonFile     *os.File
	csvFile      *os.File
	events       []StructuredEvent
	maxEvents    int
	enableJSON   bool
	enableCSV    bool
	enableStdout bool
}

// NewStructuredLogger creates a new structured logger
func NewStructuredLogger(jsonPath, csvPath string, maxEvents int) (*StructuredLogger, error) {
	sl := &StructuredLogger{
		events:       make([]StructuredEvent, 0),
		maxEvents:    maxEvents,
		enableJSON:   jsonPath != "",
		enableCSV:    csvPath != "",
		enableStdout: true,
	}

	var err error

	// Open JSON file if specified
	if jsonPath != "" {
		sl.jsonFile, err = os.OpenFile(jsonPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open JSON log file: %w", err)
		}
	}

	// Open CSV file if specified
	if csvPath != "" {
		sl.csvFile, err = os.OpenFile(csvPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open CSV log file: %w", err)
		}

		// Write CSV header if file is new
		fi, _ := sl.csvFile.Stat()
		if fi.Size() == 0 {
			header := "Timestamp,EventID,EventType,Severity,SourceIP,Method,URL,StatusCode,Blocked,RuleID,RuleName,Reason\n"
			sl.csvFile.WriteString(header)
		}
	}

	return sl, nil
}

// LogEvent logs a structured event
func (sl *StructuredLogger) LogEvent(event StructuredEvent) error {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	// Set timestamp if not already set
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Store in memory
	sl.events = append(sl.events, event)
	if len(sl.events) > sl.maxEvents {
		sl.events = sl.events[1:]
	}

	// Write to JSON file
	if sl.enableJSON && sl.jsonFile != nil {
		data, _ := json.Marshal(event)
		sl.jsonFile.WriteString(string(data) + "\n")
	}

	// Write to CSV file
	if sl.enableCSV && sl.csvFile != nil {
		csvLine := fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,%d,%v,%s,%s,%s\n",
			event.Timestamp.Format(time.RFC3339),
			event.EventID,
			event.EventType,
			event.Severity,
			event.SourceIP,
			event.Method,
			event.URL,
			event.StatusCode,
			event.Blocked,
			event.RuleID,
			event.RuleName,
			event.Reason,
		)
		sl.csvFile.WriteString(csvLine)
	}

	// Print to stdout if enabled
	if sl.enableStdout {
		sl.printEvent(event)
	}

	return nil
}

// printEvent prints an event to stdout with color coding
func (sl *StructuredLogger) printEvent(event StructuredEvent) {
	color := "\033[0m" // Reset
	switch event.Severity {
	case "critical":
		color = "\033[91m" // Bright red
	case "high":
		color = "\033[31m" // Red
	case "medium":
		color = "\033[33m" // Yellow
	case "low":
		color = "\033[36m" // Cyan
	}

	blockedStr := "✓"
	if event.Blocked {
		blockedStr = "✗"
	}

	fmt.Printf("%s[%s] %s %s %s %s %d %s %s\033[0m\n",
		color,
		event.Timestamp.Format("15:04:05"),
		blockedStr,
		event.Method,
		event.URL,
		event.SourceIP,
		event.StatusCode,
		event.RuleName,
		event.Reason,
	)
}

// ExportJSON exports all events to a JSON file
func (sl *StructuredLogger) ExportJSON(filePath string) error {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	data, err := json.MarshalIndent(sl.events, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal events: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write JSON file: %w", err)
	}

	return nil
}

// ExportCSV exports all events to a CSV file
func (sl *StructuredLogger) ExportCSV(filePath string) error {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create CSV file: %w", err)
	}
	defer file.Close()

	// Write header
	header := "Timestamp,EventID,EventType,Severity,SourceIP,Method,URL,StatusCode,Blocked,RuleID,RuleName,Reason\n"
	file.WriteString(header)

	// Write events
	for _, event := range sl.events {
		csvLine := fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,%d,%v,%s,%s,%s\n",
			event.Timestamp.Format(time.RFC3339),
			event.EventID,
			event.EventType,
			event.Severity,
			event.SourceIP,
			event.Method,
			event.URL,
			event.StatusCode,
			event.Blocked,
			event.RuleID,
			event.RuleName,
			event.Reason,
		)
		file.WriteString(csvLine)
	}

	return nil
}

// GetEvents returns all logged events
func (sl *StructuredLogger) GetEvents() []StructuredEvent {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	events := make([]StructuredEvent, len(sl.events))
	copy(events, sl.events)
	return events
}

// GetEventsBySeverity returns events filtered by severity
func (sl *StructuredLogger) GetEventsBySeverity(severity string) []StructuredEvent {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	var filtered []StructuredEvent
	for _, event := range sl.events {
		if event.Severity == severity {
			filtered = append(filtered, event)
		}
	}
	return filtered
}

// GetBlockedEvents returns only blocked events
func (sl *StructuredLogger) GetBlockedEvents() []StructuredEvent {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	var filtered []StructuredEvent
	for _, event := range sl.events {
		if event.Blocked {
			filtered = append(filtered, event)
		}
	}
	return filtered
}

// GetEventsByRule returns events filtered by rule ID
func (sl *StructuredLogger) GetEventsByRule(ruleID string) []StructuredEvent {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	var filtered []StructuredEvent
	for _, event := range sl.events {
		if event.RuleID == ruleID {
			filtered = append(filtered, event)
		}
	}
	return filtered
}

// Close closes the log files
func (sl *StructuredLogger) Close() error {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	if sl.jsonFile != nil {
		sl.jsonFile.Close()
	}

	if sl.csvFile != nil {
		sl.csvFile.Close()
	}

	return nil
}

// GetStatistics returns statistics about logged events
func (sl *StructuredLogger) GetStatistics() map[string]interface{} {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	totalEvents := len(sl.events)
	blockedCount := 0
	allowedCount := 0
	severityCount := make(map[string]int)
	ruleCount := make(map[string]int)

	for _, event := range sl.events {
		if event.Blocked {
			blockedCount++
		} else {
			allowedCount++
		}
		severityCount[event.Severity]++
		if event.RuleID != "" {
			ruleCount[event.RuleID]++
		}
	}

	return map[string]interface{}{
		"total_events":     totalEvents,
		"blocked_events":   blockedCount,
		"allowed_events":   allowedCount,
		"block_rate":       float64(blockedCount) / float64(totalEvents) * 100,
		"severity_count":   severityCount,
		"rule_count":       ruleCount,
	}
}
