# Rule Efficacy and False Positive Analysis

## Overview

The Rule Efficacy Analysis module helps security researchers and WAF operators measure the effectiveness of their security rules. By analyzing structured logs, you can identify high-performing rules, detect false positive patterns, and optimize your WAF configuration for better security and reduced operational overhead.

## Key Metrics

### Performance Metrics

**Precision (Positive Predictive Value)**
- Formula: TP / (TP + FP)
- Meaning: Of all the requests we blocked, how many were actually attacks?
- Target: > 0.95 (less than 5% false positive rate)

**Recall (Sensitivity)**
- Formula: TP / (TP + FN)
- Meaning: Of all actual attacks, how many did we catch?
- Target: > 0.90 (catch at least 90% of attacks)

**F1-Score**
- Formula: 2 × (Precision × Recall) / (Precision + Recall)
- Meaning: Harmonic mean of precision and recall
- Target: > 0.90 (balanced performance)

**Specificity (True Negative Rate)**
- Formula: TN / (TN + FP)
- Meaning: Of all legitimate traffic, how much did we allow?
- Target: > 0.99 (allow 99% of legitimate traffic)

**Block Rate**
- Formula: (Blocked Requests / Total Requests) × 100
- Meaning: Percentage of traffic being blocked
- Target: 1-5% (depends on environment)

### Latency Metrics

- **Average Latency**: Mean response time for rule evaluation
- **Min/Max Latency**: Performance range
- **Target**: < 5ms per rule

## Usage

### Basic Report Generation

```bash
# Generate a comprehensive JSON report
shieldcli efficacy report \
  --log-file events.json \
  --output report.json \
  --format json

# Generate a human-readable text report
shieldcli efficacy report \
  --log-file events.json \
  --output report.txt \
  --format text

# Generate a CSV report for spreadsheet analysis
shieldcli efficacy report \
  --log-file events.json \
  --output report.csv \
  --format csv
```

### Identify Top Performing Rules

```bash
# Show top 10 rules by F1-score
shieldcli efficacy top 10 --log-file events.json

# Show top 5 rules
shieldcli efficacy top 5 --log-file events.json
```

### Find Problematic Rules

```bash
# Identify rules with high false positive rates
shieldcli efficacy problematic --log-file events.json
```

### Compare Rules

```bash
# Compare SQL Injection rule (1001) with XSS rule (1002)
shieldcli efficacy compare 1001 1002 --log-file events.json
```

## Report Structure

### JSON Report Format

```json
{
  "summary": {
    "total_requests": 50000,
    "total_blocked": 2500,
    "block_rate": 5.0,
    "total_rules": 6,
    "avg_f1_score": 0.92,
    "avg_precision": 0.95,
    "avg_recall": 0.88,
    "analysis_start": "2025-12-01T10:00:00Z",
    "analysis_end": "2025-12-01T20:00:00Z",
    "analysis_duration": "10h0m0s"
  },
  "rules": {
    "1001": {
      "rule_id": "1001",
      "rule_name": "SQL Injection",
      "total_triggers": 1523,
      "true_positives": 1450,
      "false_positives": 73,
      "precision": 0.952,
      "recall": 0.890,
      "f1_score": 0.920,
      "block_rate": 95.2,
      "avg_latency_ms": 2.3,
      "attack_patterns": [
        "UNION-based SQLi",
        "Time-based blind SQLi",
        "Error-based SQLi"
      ],
      "top_blocked_ips": {
        "192.168.1.100": 45,
        "10.0.0.50": 32
      },
      "recommendations": [
        "Consider whitelist for /api/health endpoint",
        "Reduce sensitivity for POST parameters on /admin"
      ]
    }
  },
  "top_10": [...],
  "problems": [...]
}
```

## Analysis Scenarios

### Scenario 1: High False Positive Rate

**Symptoms:**
- Precision < 0.80
- Many legitimate users reporting blocked requests
- Block rate > 10%

**Investigation:**
```bash
# Find problematic rules
shieldcli efficacy problematic --log-file events.json

# Compare with other rules
shieldcli efficacy compare 1001 1002 --log-file events.json
```

**Actions:**
1. Review top blocked IPs and URLs
2. Add whitelists for legitimate traffic patterns
3. Reduce rule sensitivity
4. Combine with other rules for better context

### Scenario 2: Low Detection Rate

**Symptoms:**
- Recall < 0.70
- Known attacks are not being blocked
- F1-Score < 0.80

**Investigation:**
```bash
# Analyze rule performance
shieldcli efficacy report --log-file events.json --format text

# Check attack patterns
shieldcli efficacy top 10 --log-file events.json
```

**Actions:**
1. Review attack patterns in logs
2. Expand rule patterns to cover variants
3. Combine multiple rules for detection
4. Test with known attack payloads

### Scenario 3: Performance Degradation

**Symptoms:**
- Average latency > 5ms
- High CPU usage
- Response times increasing

**Investigation:**
```bash
# Generate performance report
shieldcli efficacy report --log-file events.json --format json | grep latency
```

**Actions:**
1. Optimize regex patterns
2. Disable low-value rules
3. Use simpler pattern matching
4. Consider rule caching

## Integration with Data Analysis Tools

### Python/Pandas Analysis

```python
import pandas as pd
import json

# Load report
with open('report.json') as f:
    report = json.load(f)

# Convert to DataFrame
rules_data = []
for rule_id, metrics in report['rules'].items():
    rules_data.append(metrics)

df = pd.DataFrame(rules_data)

# Analyze
print("High precision rules:")
print(df[df['precision'] > 0.95][['rule_name', 'precision', 'recall']])

print("\nProblematic rules:")
print(df[df['precision'] < 0.80][['rule_name', 'precision', 'false_positives']])

# Visualization
import matplotlib.pyplot as plt
df.plot(x='rule_name', y=['precision', 'recall'], kind='bar')
plt.show()
```

### R Analysis

```r
library(jsonlite)
library(dplyr)
library(ggplot2)

# Load report
report <- fromJSON('report.json')
rules <- as.data.frame(do.call(rbind, report$rules))

# Analyze
rules %>%
  arrange(desc(f1_score)) %>%
  head(10) %>%
  select(rule_name, precision, recall, f1_score)

# Visualize
ggplot(rules, aes(x = precision, y = recall, label = rule_name)) +
  geom_point(aes(size = total_triggers, color = f1_score)) +
  geom_text(hjust = 0, vjust = 0) +
  theme_minimal()
```

## Best Practices

### 1. Regular Analysis

- Analyze logs weekly or after significant traffic changes
- Track metrics over time to identify trends
- Compare before/after rule changes

### 2. Baseline Establishment

- Establish baseline metrics for each rule
- Set targets based on your security requirements
- Document why certain rules have different targets

### 3. False Positive Management

- Maintain a whitelist of legitimate traffic patterns
- Review and validate all blocks in first 24 hours
- Adjust rules based on false positive patterns

### 4. Performance Optimization

- Monitor latency metrics
- Disable rules with high latency and low effectiveness
- Consider rule ordering (fast rules first)

### 5. Documentation

- Document why each rule is enabled
- Record rule changes and their impact
- Share findings with security team

## Troubleshooting

### No Events Found

**Problem:** Report shows 0 events

**Solution:**
1. Verify log file path is correct
2. Ensure log file contains valid JSON
3. Check that events have required fields (rule_id, blocked, etc.)

### Low Metrics Across All Rules

**Problem:** All rules show low precision/recall

**Solution:**
1. Verify events are properly classified
2. Check if rules are actually being triggered
3. Review rule configuration

### High Memory Usage

**Problem:** Analysis takes too long or runs out of memory

**Solution:**
1. Split analysis into smaller time windows
2. Filter events before analysis
3. Use CSV format instead of JSON

## Recommendations Engine

The analyzer automatically generates recommendations based on metrics:

- **High FP Rate**: "High false positive rate (X%). Consider tuning rule sensitivity or adding whitelists."
- **Low Recall**: "Low recall rate (X%). Rule may be missing attack variants. Consider expanding patterns."
- **High Latency**: "High average latency (Xms). Consider optimizing rule patterns for better performance."
- **Low Block Rate**: "Low block rate suggests many false positives. Review and refine rule patterns."
- **High Block Rate**: "Very high block rate. Verify this is intentional and not over-blocking legitimate traffic."

## Advanced Analysis

### Rule Correlation

Identify rules that often trigger together:

```python
# Load events
events = [json.loads(line) for line in open('events.json')]

# Create correlation matrix
import numpy as np
rules = set(e['rule_id'] for e in events if 'rule_id' in e)
correlation = np.zeros((len(rules), len(rules)))

# Calculate co-occurrence
for event in events:
    if 'rule_id' in event:
        rule_idx = list(rules).index(event['rule_id'])
        # Find other rules triggered in same request
        # ... calculate correlation
```

### Attack Pattern Clustering

Group similar attacks:

```python
from sklearn.cluster import KMeans

# Extract payloads
payloads = [e['payload'] for e in events if 'payload' in e]

# Vectorize and cluster
from sklearn.feature_extraction.text import TfidfVectorizer
vectorizer = TfidfVectorizer()
X = vectorizer.fit_transform(payloads)
kmeans = KMeans(n_clusters=5)
clusters = kmeans.fit_predict(X)
```

## References

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Precision and Recall](https://en.wikipedia.org/wiki/Precision_and_recall)
- [F1-Score](https://en.wikipedia.org/wiki/F-score)
- [ROC Curves](https://en.wikipedia.org/wiki/Receiver_operating_characteristic)
