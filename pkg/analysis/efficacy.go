package analysis

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"time"
)

// RuleMetrics represents performance metrics for a single WAF rule
type RuleMetrics struct {
	RuleID              string                 `json:"rule_id"`
	RuleName            string                 `json:"rule_name"`
	TotalTriggers       int64                  `json:"total_triggers"`
	TruePositives       int64                  `json:"true_positives"`
	FalsePositives      int64                  `json:"false_positives"`
	TrueNegatives       int64                  `json:"true_negatives"`
	FalseNegatives      int64                  `json:"false_negatives"`
	Precision           float64                `json:"precision"`
	Recall              float64                `json:"recall"`
	F1Score             float64                `json:"f1_score"`
	Specificity         float64                `json:"specificity"`
	Accuracy            float64                `json:"accuracy"`
	AvgLatencyMs        float64                `json:"avg_latency_ms"`
	MaxLatencyMs        float64                `json:"max_latency_ms"`
	MinLatencyMs        float64                `json:"min_latency_ms"`
	BlockRate           float64                `json:"block_rate"`
	AttackPatterns      []string               `json:"attack_patterns"`
	TopBlockedIPs       map[string]int64       `json:"top_blocked_ips"`
	TopBlockedURLs      map[string]int64       `json:"top_blocked_urls"`
	Recommendations     []string               `json:"recommendations"`
	LastUpdated         time.Time              `json:"last_updated"`
	TimeWindow          string                 `json:"time_window"`
}

// EfficacyAnalyzer analyzes WAF rule performance
type EfficacyAnalyzer struct {
	mu                  sync.RWMutex
	ruleMetrics         map[string]*RuleMetrics
	events              []map[string]interface{}
	totalRequests       int64
	totalBlocked        int64
	analysisStartTime   time.Time
	analysisEndTime     time.Time
	falsePositiveThresh float64 // Threshold for identifying FP patterns
}

// NewEfficacyAnalyzer creates a new efficacy analyzer
func NewEfficacyAnalyzer() *EfficacyAnalyzer {
	return &EfficacyAnalyzer{
		ruleMetrics:         make(map[string]*RuleMetrics),
		events:              make([]map[string]interface{}, 0),
		analysisStartTime:   time.Now(),
		falsePositiveThresh: 0.1, // 10% FP threshold
	}
}

// AddEvent adds an event for analysis
func (ea *EfficacyAnalyzer) AddEvent(event map[string]interface{}) {
	ea.mu.Lock()
	defer ea.mu.Unlock()

	ea.events = append(ea.events, event)
	ea.totalRequests++

	// Track blocked events
	if blocked, ok := event["blocked"].(bool); ok && blocked {
		ea.totalBlocked++
	}
}

// AnalyzeRules performs efficacy analysis on all rules
func (ea *EfficacyAnalyzer) AnalyzeRules() error {
	ea.mu.Lock()
	defer ea.mu.Unlock()

	ea.analysisEndTime = time.Now()

	// Group events by rule
	ruleEvents := make(map[string][]map[string]interface{})

	for _, event := range ea.events {
		ruleID, ok := event["rule_id"].(string)
		if !ok || ruleID == "" {
			continue
		}

		ruleEvents[ruleID] = append(ruleEvents[ruleID], event)
	}

	// Calculate metrics for each rule
	for ruleID, events := range ruleEvents {
		metrics := ea.calculateRuleMetrics(ruleID, events)
		metrics.Recommendations = ea.generateRecommendations(metrics)
		ea.ruleMetrics[ruleID] = metrics
	}

	return nil
}

// calculateRuleMetrics calculates metrics for a specific rule
func (ea *EfficacyAnalyzer) calculateRuleMetrics(ruleID string, events []map[string]interface{}) *RuleMetrics {
	metrics := &RuleMetrics{
		RuleID:          ruleID,
		TotalTriggers:   int64(len(events)),
		TopBlockedIPs:   make(map[string]int64),
		TopBlockedURLs:  make(map[string]int64),
		AttackPatterns:  make([]string, 0),
		LastUpdated:     time.Now(),
		TimeWindow:      fmt.Sprintf("%s to %s", ea.analysisStartTime.Format(time.RFC3339), ea.analysisEndTime.Format(time.RFC3339)),
	}

	var totalLatency float64
	var minLatency float64 = math.MaxFloat64
	var maxLatency float64 = 0

	patternMap := make(map[string]bool)
	ipCounts := make(map[string]int64)
	urlCounts := make(map[string]int64)

	for _, event := range events {
		// Extract metrics
		if blocked, ok := event["blocked"].(bool); ok && blocked {
			metrics.TruePositives++
		} else {
			metrics.FalsePositives++
		}

		// Latency
		if latency, ok := event["response_time_ms"].(float64); ok {
			totalLatency += latency
			if latency < minLatency {
				minLatency = latency
			}
			if latency > maxLatency {
				maxLatency = latency
			}
		}

		// Attack patterns
		if reason, ok := event["reason"].(string); ok && reason != "" {
			patternMap[reason] = true
		}

		// Top IPs
		if ip, ok := event["source_ip"].(string); ok {
			ipCounts[ip]++
		}

		// Top URLs
		if url, ok := event["url"].(string); ok {
			urlCounts[url]++
		}

		// Rule name
		if ruleName, ok := event["rule_name"].(string); ok {
			metrics.RuleName = ruleName
		}
	}

	// Calculate averages
	if len(events) > 0 {
		metrics.AvgLatencyMs = totalLatency / float64(len(events))
		if minLatency != math.MaxFloat64 {
			metrics.MinLatencyMs = minLatency
		}
		metrics.MaxLatencyMs = maxLatency
	}

	// Calculate precision, recall, F1
	if metrics.TruePositives+metrics.FalsePositives > 0 {
		metrics.Precision = float64(metrics.TruePositives) / float64(metrics.TruePositives+metrics.FalsePositives)
	}

	if metrics.TruePositives+metrics.FalseNegatives > 0 {
		metrics.Recall = float64(metrics.TruePositives) / float64(metrics.TruePositives+metrics.FalseNegatives)
	}

	if metrics.Precision+metrics.Recall > 0 {
		metrics.F1Score = 2 * (metrics.Precision * metrics.Recall) / (metrics.Precision + metrics.Recall)
	}

	// Block rate
	if metrics.TotalTriggers > 0 {
		metrics.BlockRate = float64(metrics.TruePositives) / float64(metrics.TotalTriggers) * 100
	}

	// Populate attack patterns
	for pattern := range patternMap {
		metrics.AttackPatterns = append(metrics.AttackPatterns, pattern)
	}

	// Top IPs
	metrics.TopBlockedIPs = ea.getTopN(ipCounts, 10)

	// Top URLs
	metrics.TopBlockedURLs = ea.getTopN(urlCounts, 10)

	return metrics
}

// getTopN returns the top N entries from a map
func (ea *EfficacyAnalyzer) getTopN(m map[string]int64, n int) map[string]int64 {
	type kv struct {
		Key   string
		Value int64
	}

	var sorted []kv
	for k, v := range m {
		sorted = append(sorted, kv{k, v})
	}

	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Value > sorted[j].Value
	})

	result := make(map[string]int64)
	for i := 0; i < len(sorted) && i < n; i++ {
		result[sorted[i].Key] = sorted[i].Value
	}

	return result
}

// generateRecommendations generates recommendations based on metrics
func (ea *EfficacyAnalyzer) generateRecommendations(metrics *RuleMetrics) []string {
	recommendations := make([]string, 0)

	// High false positive rate
	if metrics.FalsePositives > 0 && metrics.Precision < 0.8 {
		recommendations = append(recommendations,
			fmt.Sprintf("High false positive rate (%.1f%%). Consider tuning rule sensitivity or adding whitelists.", (1-metrics.Precision)*100))
	}

	// Low recall
	if metrics.Recall < 0.7 && metrics.Recall > 0 {
		recommendations = append(recommendations,
			fmt.Sprintf("Low recall rate (%.1f%%). Rule may be missing attack variants. Consider expanding patterns.", metrics.Recall*100))
	}

	// High latency
	if metrics.AvgLatencyMs > 5 {
		recommendations = append(recommendations,
			fmt.Sprintf("High average latency (%.2fms). Consider optimizing rule patterns for better performance.", metrics.AvgLatencyMs))
	}

	// Low block rate
	if metrics.BlockRate < 50 && metrics.TotalTriggers > 100 {
		recommendations = append(recommendations,
			"Low block rate suggests many false positives. Review and refine rule patterns.")
	}

	// High block rate
	if metrics.BlockRate > 95 && metrics.TotalTriggers > 100 {
		recommendations = append(recommendations,
			"Very high block rate. Verify this is intentional and not over-blocking legitimate traffic.")
	}

	return recommendations
}

// GetRuleMetrics returns metrics for a specific rule
func (ea *EfficacyAnalyzer) GetRuleMetrics(ruleID string) *RuleMetrics {
	ea.mu.RLock()
	defer ea.mu.RUnlock()

	if metrics, ok := ea.ruleMetrics[ruleID]; ok {
		return metrics
	}

	return nil
}

// GetAllMetrics returns metrics for all rules
func (ea *EfficacyAnalyzer) GetAllMetrics() map[string]*RuleMetrics {
	ea.mu.RLock()
	defer ea.mu.RUnlock()

	result := make(map[string]*RuleMetrics)
	for k, v := range ea.ruleMetrics {
		result[k] = v
	}

	return result
}

// GetTopRules returns the top N rules by F1 score
func (ea *EfficacyAnalyzer) GetTopRules(n int) []*RuleMetrics {
	ea.mu.RLock()
	defer ea.mu.RUnlock()

	var rules []*RuleMetrics
	for _, metrics := range ea.ruleMetrics {
		rules = append(rules, metrics)
	}

	sort.Slice(rules, func(i, j int) bool {
		return rules[i].F1Score > rules[j].F1Score
	})

	if len(rules) > n {
		return rules[:n]
	}

	return rules
}

// GetProblematicRules returns rules with high false positive rates
func (ea *EfficacyAnalyzer) GetProblematicRules() []*RuleMetrics {
	ea.mu.RLock()
	defer ea.mu.RUnlock()

	var problematic []*RuleMetrics
	for _, metrics := range ea.ruleMetrics {
		if metrics.FalsePositives > 0 && metrics.Precision < 0.8 {
			problematic = append(problematic, metrics)
		}
	}

	sort.Slice(problematic, func(i, j int) bool {
		return problematic[i].FalsePositives > problematic[j].FalsePositives
	})

	return problematic
}

// CompareRules compares two rules and returns differences
func (ea *EfficacyAnalyzer) CompareRules(ruleID1, ruleID2 string) map[string]interface{} {
	ea.mu.RLock()
	defer ea.mu.RUnlock()

	metrics1, ok1 := ea.ruleMetrics[ruleID1]
	metrics2, ok2 := ea.ruleMetrics[ruleID2]

	if !ok1 || !ok2 {
		return nil
	}

	return map[string]interface{}{
		"rule_1": map[string]interface{}{
			"id":         metrics1.RuleID,
			"name":       metrics1.RuleName,
			"f1_score":   metrics1.F1Score,
			"precision":  metrics1.Precision,
			"recall":     metrics1.Recall,
			"block_rate": metrics1.BlockRate,
		},
		"rule_2": map[string]interface{}{
			"id":         metrics2.RuleID,
			"name":       metrics2.RuleName,
			"f1_score":   metrics2.F1Score,
			"precision":  metrics2.Precision,
			"recall":     metrics2.Recall,
			"block_rate": metrics2.BlockRate,
		},
		"difference": map[string]interface{}{
			"f1_score_diff":   metrics1.F1Score - metrics2.F1Score,
			"precision_diff":  metrics1.Precision - metrics2.Precision,
			"recall_diff":     metrics1.Recall - metrics2.Recall,
			"block_rate_diff": metrics1.BlockRate - metrics2.BlockRate,
		},
	}
}

// GetSummary returns a summary of all analysis
func (ea *EfficacyAnalyzer) GetSummary() map[string]interface{} {
	ea.mu.RLock()
	defer ea.mu.RUnlock()

	totalRules := len(ea.ruleMetrics)
	var avgF1Score float64
	var avgPrecision float64
	var avgRecall float64

	for _, metrics := range ea.ruleMetrics {
		avgF1Score += metrics.F1Score
		avgPrecision += metrics.Precision
		avgRecall += metrics.Recall
	}

	if totalRules > 0 {
		avgF1Score /= float64(totalRules)
		avgPrecision /= float64(totalRules)
		avgRecall /= float64(totalRules)
	}

	return map[string]interface{}{
		"total_requests":     ea.totalRequests,
		"total_blocked":      ea.totalBlocked,
		"block_rate":         float64(ea.totalBlocked) / float64(ea.totalRequests) * 100,
		"total_rules":        totalRules,
		"avg_f1_score":       avgF1Score,
		"avg_precision":      avgPrecision,
		"avg_recall":         avgRecall,
		"analysis_start":     ea.analysisStartTime.Format(time.RFC3339),
		"analysis_end":       ea.analysisEndTime.Format(time.RFC3339),
		"analysis_duration":  ea.analysisEndTime.Sub(ea.analysisStartTime).String(),
	}
}
