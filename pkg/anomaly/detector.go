package anomaly

import (
	"fmt"
	"math"
	"sync"
	"time"
)

// AnomalyDetector performs statistical anomaly detection on HTTP traffic
type AnomalyDetector struct {
	mu                    sync.RWMutex
	requestStats          *RequestStatistics
	payloadStats          *PayloadStatistics
	timeWindowSize        time.Duration
	requestRateThreshold  float64
	payloadSizeThreshold  float64
	entropyThreshold      float64
	anomalies             []Anomaly
}

// RequestStatistics tracks request-level metrics
type RequestStatistics struct {
	TotalRequests       int64
	RequestsPerSecond   float64
	AveragePayloadSize  float64
	PayloadSizeStdDev   float64
	PayloadSizes        []int64
	RequestTimestamps   []time.Time
	UniqueUserAgents    map[string]int64
	UniqueIPs           map[string]int64
}

// PayloadStatistics tracks payload-level metrics
type PayloadStatistics struct {
	AverageEntropy      float64
	EntropyStdDev       float64
	EntropyValues       []float64
	SuspiciousPatterns  int64
	EncodedPayloads     int64
	LargePayloads       int64
}

// Anomaly represents a detected anomaly
type Anomaly struct {
	Timestamp   time.Time
	Type        string // "request_rate", "payload_size", "entropy", "user_agent", "ip_address"
	Severity    string // "low", "medium", "high", "critical"
	Value       float64
	Threshold   float64
	Description string
	RequestID   string
}

// NewAnomalyDetector creates a new anomaly detector
func NewAnomalyDetector(timeWindowSize time.Duration) *AnomalyDetector {
	return &AnomalyDetector{
		requestStats:         &RequestStatistics{
			UniqueUserAgents: make(map[string]int64),
			UniqueIPs:        make(map[string]int64),
		},
		payloadStats:         &PayloadStatistics{},
		timeWindowSize:       timeWindowSize,
		requestRateThreshold: 1000.0, // requests per second
		payloadSizeThreshold: 10 * 1024 * 1024, // 10MB
		entropyThreshold:     4.5,
		anomalies:            make([]Anomaly, 0),
	}
}

// RecordRequest records a new request for analysis
func (ad *AnomalyDetector) RecordRequest(ip string, userAgent string, payloadSize int64, entropy float64) {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	ad.requestStats.TotalRequests++
	ad.requestStats.RequestTimestamps = append(ad.requestStats.RequestTimestamps, time.Now())
	ad.requestStats.PayloadSizes = append(ad.requestStats.PayloadSizes, payloadSize)
	ad.requestStats.UniqueIPs[ip]++
	ad.requestStats.UniqueUserAgents[userAgent]++

	ad.payloadStats.EntropyValues = append(ad.payloadStats.EntropyValues, entropy)

	// Detect anomalies
	ad.detectAnomalies(ip, userAgent, payloadSize, entropy)
}

// detectAnomalies checks for statistical anomalies
func (ad *AnomalyDetector) detectAnomalies(ip string, userAgent string, payloadSize int64, entropy float64) {
	// Request rate anomaly
	if len(ad.requestStats.RequestTimestamps) > 1 {
		rps := ad.calculateRequestsPerSecond()
		if rps > ad.requestRateThreshold {
			ad.anomalies = append(ad.anomalies, Anomaly{
				Timestamp:   time.Now(),
				Type:        "request_rate",
				Severity:    "high",
				Value:       rps,
				Threshold:   ad.requestRateThreshold,
				Description: fmt.Sprintf("Abnormally high request rate: %.2f req/s", rps),
			})
		}
	}

	// Payload size anomaly
	if payloadSize > int64(ad.payloadSizeThreshold) {
		ad.anomalies = append(ad.anomalies, Anomaly{
			Timestamp:   time.Now(),
			Type:        "payload_size",
			Severity:    "medium",
			Value:       float64(payloadSize),
			Threshold:   ad.payloadSizeThreshold,
			Description: fmt.Sprintf("Unusually large payload: %d bytes", payloadSize),
		})
		ad.payloadStats.LargePayloads++
	}

	// Entropy anomaly
	if entropy > ad.entropyThreshold {
		ad.anomalies = append(ad.anomalies, Anomaly{
			Timestamp:   time.Now(),
			Type:        "entropy",
			Severity:    "medium",
			Value:       entropy,
			Threshold:   ad.entropyThreshold,
			Description: fmt.Sprintf("High entropy payload detected: %.2f", entropy),
		})
		ad.payloadStats.EncodedPayloads++
	}

	// User-Agent anomaly (if it's a bot or unusual)
	if ad.isAnomalousUserAgent(userAgent) {
		ad.anomalies = append(ad.anomalies, Anomaly{
			Timestamp:   time.Now(),
			Type:        "user_agent",
			Severity:    "low",
			Description: fmt.Sprintf("Suspicious user agent: %s", userAgent),
		})
	}

	// IP-based anomaly detection
	if ad.requestStats.UniqueIPs[ip] > 100 { // More than 100 requests from same IP
		ad.anomalies = append(ad.anomalies, Anomaly{
			Timestamp:   time.Now(),
			Type:        "ip_address",
			Severity:    "medium",
			Value:       float64(ad.requestStats.UniqueIPs[ip]),
			Description: fmt.Sprintf("High request volume from IP %s: %d requests", ip, ad.requestStats.UniqueIPs[ip]),
		})
	}
}

// calculateRequestsPerSecond calculates the current request rate
func (ad *AnomalyDetector) calculateRequestsPerSecond() float64 {
	if len(ad.requestStats.RequestTimestamps) < 2 {
		return 0
	}

	// Get timestamps from the last second
	now := time.Now()
	oneSecondAgo := now.Add(-time.Second)

	count := 0
	for _, ts := range ad.requestStats.RequestTimestamps {
		if ts.After(oneSecondAgo) {
			count++
		}
	}

	return float64(count)
}

// isAnomalousUserAgent checks if a user agent is suspicious
func (ad *AnomalyDetector) isAnomalousUserAgent(userAgent string) bool {
	suspiciousAgents := []string{
		"BadBot", "SQLMap", "Nikto", "Nmap", "Masscan", "Nessus",
		"OpenVAS", "Metasploit", "Burp", "Zaproxy", "curl", "wget",
	}

	for _, agent := range suspiciousAgents {
		if agent == userAgent {
			return true
		}
	}

	return false
}

// GetStatistics returns current statistics
func (ad *AnomalyDetector) GetStatistics() map[string]interface{} {
	ad.mu.RLock()
	defer ad.mu.RUnlock()

	avgPayloadSize := 0.0
	if len(ad.requestStats.PayloadSizes) > 0 {
		sum := int64(0)
		for _, size := range ad.requestStats.PayloadSizes {
			sum += size
		}
		avgPayloadSize = float64(sum) / float64(len(ad.requestStats.PayloadSizes))
	}

	avgEntropy := 0.0
	if len(ad.payloadStats.EntropyValues) > 0 {
		sum := 0.0
		for _, e := range ad.payloadStats.EntropyValues {
			sum += e
		}
		avgEntropy = sum / float64(len(ad.payloadStats.EntropyValues))
	}

	return map[string]interface{}{
		"total_requests":       ad.requestStats.TotalRequests,
		"unique_ips":           len(ad.requestStats.UniqueIPs),
		"unique_user_agents":   len(ad.requestStats.UniqueUserAgents),
		"avg_payload_size":     avgPayloadSize,
		"avg_entropy":          avgEntropy,
		"large_payloads":       ad.payloadStats.LargePayloads,
		"encoded_payloads":     ad.payloadStats.EncodedPayloads,
		"total_anomalies":      len(ad.anomalies),
	}
}

// GetAnomalies returns all detected anomalies
func (ad *AnomalyDetector) GetAnomalies() []Anomaly {
	ad.mu.RLock()
	defer ad.mu.RUnlock()

	// Return a copy to avoid external modifications
	anomalies := make([]Anomaly, len(ad.anomalies))
	copy(anomalies, ad.anomalies)
	return anomalies
}

// GetAnomaliesBySeverity returns anomalies filtered by severity
func (ad *AnomalyDetector) GetAnomaliesBySeverity(severity string) []Anomaly {
	ad.mu.RLock()
	defer ad.mu.RUnlock()

	var filtered []Anomaly
	for _, a := range ad.anomalies {
		if a.Severity == severity {
			filtered = append(filtered, a)
		}
	}
	return filtered
}

// ClearAnomalies clears all recorded anomalies
func (ad *AnomalyDetector) ClearAnomalies() {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	ad.anomalies = make([]Anomaly, 0)
}

// CalculateStandardDeviation calculates the standard deviation of payload sizes
func (ad *AnomalyDetector) CalculateStandardDeviation() float64 {
	ad.mu.RLock()
	defer ad.mu.RUnlock()

	if len(ad.requestStats.PayloadSizes) < 2 {
		return 0
	}

	// Calculate mean
	sum := int64(0)
	for _, size := range ad.requestStats.PayloadSizes {
		sum += size
	}
	mean := float64(sum) / float64(len(ad.requestStats.PayloadSizes))

	// Calculate variance
	variance := 0.0
	for _, size := range ad.requestStats.PayloadSizes {
		diff := float64(size) - mean
		variance += diff * diff
	}
	variance /= float64(len(ad.requestStats.PayloadSizes))

	// Return standard deviation
	return math.Sqrt(variance)
}
