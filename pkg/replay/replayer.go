package replay

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Replayer replays recorded traffic against a target server
type Replayer struct {
	client    *http.Client
	targetURL string
	records   []TrafficRecord
	results   []ReplayResult
}

// ReplayResult represents the result of replaying a single request
type ReplayResult struct {
	OriginalRequest  RecordedRequest
	OriginalResponse RecordedResponse
	ReplayedResponse ReplayedResponse
	Timestamp        time.Time
	Success          bool
	Error            string
	StatusMatch      bool
	BodyMatch        bool
}

// ReplayedResponse represents the response from replaying a request
type ReplayedResponse struct {
	StatusCode int
	Body       string
	Duration   time.Duration
	Error      string
}

// NewReplayer creates a new traffic replayer
func NewReplayer(targetURL string) *Replayer {
	return &Replayer{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		targetURL: targetURL,
		records:   make([]TrafficRecord, 0),
		results:   make([]ReplayResult, 0),
	}
}

// LoadRecords loads traffic records from a recorder
func (r *Replayer) LoadRecords(records []TrafficRecord) {
	r.records = records
}

// ReplayAll replays all recorded requests
func (r *Replayer) ReplayAll() error {
	for _, record := range r.records {
		if err := r.ReplayRequest(record); err != nil {
			return err
		}
	}
	return nil
}

// ReplayRequest replays a single recorded request
func (r *Replayer) ReplayRequest(record TrafficRecord) error {
	startTime := time.Now()

	// Parse the URL
	parsedURL, err := url.Parse(r.targetURL + record.Request.URL)
	if err != nil {
		return fmt.Errorf("failed to parse URL: %w", err)
	}

	// Create a new request
	req, err := http.NewRequest(record.Request.Method, parsedURL.String(), bytes.NewBufferString(record.Request.Body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Copy headers from recorded request
	for key, value := range record.Request.Headers {
		req.Header.Set(key, value)
	}

	// Execute the request
	resp, err := r.client.Do(req)
	duration := time.Since(startTime)

	replayedResp := ReplayedResponse{
		Duration: duration,
	}

	if err != nil {
		replayedResp.Error = err.Error()
	} else {
		defer resp.Body.Close()
		replayedResp.StatusCode = resp.StatusCode

		// Read response body
		body, err := io.ReadAll(resp.Body)
		if err == nil {
			replayedResp.Body = string(body)
		}
	}

	// Compare results
	statusMatch := replayedResp.StatusCode == record.Response.StatusCode
	bodyMatch := replayedResp.Body == record.Response.Body

	result := ReplayResult{
		OriginalRequest:  record.Request,
		OriginalResponse: record.Response,
		ReplayedResponse: replayedResp,
		Timestamp:        time.Now(),
		Success:          err == nil,
		Error:            replayedResp.Error,
		StatusMatch:      statusMatch,
		BodyMatch:        bodyMatch,
	}

	r.results = append(r.results, result)

	return nil
}

// GetResults returns all replay results
func (r *Replayer) GetResults() []ReplayResult {
	return r.results
}

// GetResultSummary returns a summary of replay results
func (r *Replayer) GetResultSummary() map[string]interface{} {
	totalRequests := len(r.results)
	successfulRequests := 0
	statusMatches := 0
	bodyMatches := 0
	totalDuration := time.Duration(0)

	for _, result := range r.results {
		if result.Success {
			successfulRequests++
		}
		if result.StatusMatch {
			statusMatches++
		}
		if result.BodyMatch {
			bodyMatches++
		}
		totalDuration += result.ReplayedResponse.Duration
	}

	avgDuration := time.Duration(0)
	if totalRequests > 0 {
		avgDuration = totalDuration / time.Duration(totalRequests)
	}

	return map[string]interface{}{
		"total_requests":       totalRequests,
		"successful_requests":  successfulRequests,
		"status_matches":       statusMatches,
		"body_matches":         bodyMatches,
		"total_duration":       totalDuration.String(),
		"average_duration":     avgDuration.String(),
		"success_rate":         float64(successfulRequests) / float64(totalRequests) * 100,
	}
}

// ClearResults clears all replay results
func (r *Replayer) ClearResults() {
	r.results = make([]ReplayResult, 0)
}

// FilterResultsByStatus returns results filtered by HTTP status code
func (r *Replayer) FilterResultsByStatus(statusCode int) []ReplayResult {
	var filtered []ReplayResult
	for _, result := range r.results {
		if result.ReplayedResponse.StatusCode == statusCode {
			filtered = append(filtered, result)
		}
	}
	return filtered
}

// FilterResultsByMatch returns results filtered by match status
func (r *Replayer) FilterResultsByMatch(statusMatch, bodyMatch bool) []ReplayResult {
	var filtered []ReplayResult
	for _, result := range r.results {
		if result.StatusMatch == statusMatch && result.BodyMatch == bodyMatch {
			filtered = append(filtered, result)
		}
	}
	return filtered
}
