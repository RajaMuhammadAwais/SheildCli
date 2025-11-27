package replay

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// RecordedRequest represents a recorded HTTP request
type RecordedRequest struct {
	ID          string            `json:"id"`
	Timestamp   time.Time         `json:"timestamp"`
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body"`
	RemoteAddr  string            `json:"remote_addr"`
	ContentType string            `json:"content_type"`
}

// RecordedResponse represents a recorded HTTP response
type RecordedResponse struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
	Timestamp  time.Time         `json:"timestamp"`
}

// TrafficRecord represents a complete request-response pair
type TrafficRecord struct {
	Request  RecordedRequest  `json:"request"`
	Response RecordedResponse `json:"response"`
	Blocked  bool             `json:"blocked"`
	Reason   string           `json:"reason"`
}

// Recorder records HTTP traffic for later replay
type Recorder struct {
	records   []TrafficRecord
	filePath  string
	maxRecords int
}

// NewRecorder creates a new traffic recorder
func NewRecorder(filePath string, maxRecords int) *Recorder {
	return &Recorder{
		records:    make([]TrafficRecord, 0),
		filePath:   filePath,
		maxRecords: maxRecords,
	}
}

// RecordTraffic records a request-response pair
func (r *Recorder) RecordTraffic(req *http.Request, statusCode int, responseBody []byte, blocked bool, reason string) error {
	// Read request body
	var reqBody string
	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err == nil {
			reqBody = string(body)
		}
	}

	// Extract headers
	headers := make(map[string]string)
	for key, values := range req.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}

	// Create recorded request
	recordedReq := RecordedRequest{
		ID:         fmt.Sprintf("%d", time.Now().UnixNano()),
		Timestamp:  time.Now(),
		Method:     req.Method,
		URL:        req.RequestURI,
		Headers:    headers,
		Body:       reqBody,
		RemoteAddr: req.RemoteAddr,
		ContentType: req.Header.Get("Content-Type"),
	}

	// Extract response headers
	respHeaders := make(map[string]string)
	// Note: In a real implementation, you'd capture response headers from the actual response

	// Create recorded response
	recordedResp := RecordedResponse{
		StatusCode: statusCode,
		Headers:    respHeaders,
		Body:       string(responseBody),
		Timestamp:  time.Now(),
	}

	// Create traffic record
	record := TrafficRecord{
		Request:  recordedReq,
		Response: recordedResp,
		Blocked:  blocked,
		Reason:   reason,
	}

	r.records = append(r.records, record)

	// Limit the number of records in memory
	if len(r.records) > r.maxRecords {
		r.records = r.records[1:]
	}

	return nil
}

// SaveToFile saves all recorded traffic to a JSON file
func (r *Recorder) SaveToFile() error {
	data, err := json.MarshalIndent(r.records, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal traffic records: %w", err)
	}

	if err := os.WriteFile(r.filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write traffic file: %w", err)
	}

	return nil
}

// LoadFromFile loads traffic records from a JSON file
func (r *Recorder) LoadFromFile() error {
	data, err := os.ReadFile(r.filePath)
	if err != nil {
		return fmt.Errorf("failed to read traffic file: %w", err)
	}

	if err := json.Unmarshal(data, &r.records); err != nil {
		return fmt.Errorf("failed to unmarshal traffic records: %w", err)
	}

	return nil
}

// GetRecords returns all recorded traffic
func (r *Recorder) GetRecords() []TrafficRecord {
	return r.records
}

// GetRecordCount returns the number of recorded requests
func (r *Recorder) GetRecordCount() int {
	return len(r.records)
}

// ClearRecords clears all recorded traffic
func (r *Recorder) ClearRecords() {
	r.records = make([]TrafficRecord, 0)
}

// FilterRecordsByMethod returns records filtered by HTTP method
func (r *Recorder) FilterRecordsByMethod(method string) []TrafficRecord {
	var filtered []TrafficRecord
	for _, record := range r.records {
		if record.Request.Method == method {
			filtered = append(filtered, record)
		}
	}
	return filtered
}

// FilterRecordsByBlocked returns records filtered by blocked status
func (r *Recorder) FilterRecordsByBlocked(blocked bool) []TrafficRecord {
	var filtered []TrafficRecord
	for _, record := range r.records {
		if record.Blocked == blocked {
			filtered = append(filtered, record)
		}
	}
	return filtered
}

// ExportToCSV exports recorded traffic to a CSV file
func (r *Recorder) ExportToCSV(filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create CSV file: %w", err)
	}
	defer file.Close()

	// Write header
	_, err = file.WriteString("ID,Timestamp,Method,URL,Status,Blocked,Reason\n")
	if err != nil {
		return err
	}

	// Write records
	for _, record := range r.records {
		line := fmt.Sprintf("%s,%s,%s,%s,%d,%v,%s\n",
			record.Request.ID,
			record.Request.Timestamp.Format(time.RFC3339),
			record.Request.Method,
			record.Request.URL,
			record.Response.StatusCode,
			record.Blocked,
			record.Reason,
		)
		_, err := file.WriteString(line)
		if err != nil {
			return err
		}
	}

	return nil
}
