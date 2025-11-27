# ShieldCLI Research Features

This document describes the advanced features added to ShieldCLI for security researchers and scientists.

## 1. Statistical Anomaly Detection Module

The anomaly detection module provides researchers with statistical tools to identify unusual traffic patterns that may indicate attacks or system anomalies.

### Features

- **Request Rate Analysis**: Detects abnormally high request rates (potential DDoS)
- **Payload Size Analysis**: Identifies unusually large payloads
- **Entropy Detection**: Flags high-entropy payloads (potential encoding/obfuscation)
- **User-Agent Analysis**: Detects suspicious user agents
- **IP-based Analysis**: Identifies IPs with abnormal request volumes
- **Standard Deviation Calculation**: Computes payload size variance for statistical analysis

### Usage

```bash
# Display anomaly detection report
./shieldcli anomaly report

# Display traffic statistics
./shieldcli anomaly stats
```

### API Usage

```go
import "github.com/shieldcli/shieldcli/pkg/anomaly"

// Create detector with 1-hour time window
detector := anomaly.NewAnomalyDetector(time.Hour)

// Record a request
detector.RecordRequest(
    "192.168.1.100",           // IP address
    "Mozilla/5.0",             // User-Agent
    1024,                       // Payload size
    3.5,                        // Entropy value
)

// Get statistics
stats := detector.GetStatistics()

// Get anomalies
anomalies := detector.GetAnomalies()

// Filter by severity
criticalAnomalies := detector.GetAnomaliesBySeverity("critical")
```

### Anomaly Types

| Type | Threshold | Severity | Description |
|------|-----------|----------|-------------|
| request_rate | 1000 req/s | High | Abnormally high request rate |
| payload_size | 10MB | Medium | Unusually large payload |
| entropy | 4.5 | Medium | High-entropy payload (potential encoding) |
| user_agent | N/A | Low | Suspicious user agent detected |
| ip_address | 100 requests | Medium | High request volume from single IP |

## 2. Traffic Recording and Replay Feature

The traffic recording and replay feature enables researchers to capture real-world traffic and replay it for reproducible testing and analysis.

### Features

- **Request Recording**: Capture all HTTP requests with full details
- **Response Recording**: Store response data for comparison
- **Traffic Replay**: Replay recorded traffic against a target server
- **Result Comparison**: Compare original vs. replayed responses
- **CSV Export**: Export traffic data for analysis in external tools
- **Filtering**: Filter recorded traffic by method, status, or blocked status

### Usage

#### Recording Traffic

Enable recording when starting the proxy:

```bash
./shieldcli run \
  --proxy-to http://localhost:3000 \
  --port 8080 \
  --record-file traffic.json
```

#### Replaying Traffic

Replay recorded traffic against a target:

```bash
./shieldcli replay play \
  --input traffic.json \
  --target http://localhost:3000
```

#### Exporting Traffic

Export recorded traffic to CSV for analysis:

```bash
./shieldcli replay export \
  --input traffic.json \
  --output traffic.csv
```

### API Usage

```go
import "github.com/shieldcli/shieldcli/pkg/replay"

// Create recorder
recorder := replay.NewRecorder("traffic.json", 10000)

// Record a request-response pair
recorder.RecordTraffic(req, statusCode, responseBody, blocked, reason)

// Save to file
recorder.SaveToFile()

// Load from file
recorder.LoadFromFile()

// Export to CSV
recorder.ExportToCSV("traffic.csv")

// Create replayer
replayer := replay.NewReplayer("http://target:3000")
replayer.LoadRecords(recorder.GetRecords())

// Replay all requests
replayer.ReplayAll()

// Get results
results := replayer.GetResults()
summary := replayer.GetResultSummary()
```

### Traffic Record Format

Recorded traffic is stored in JSON format:

```json
[
  {
    "request": {
      "id": "1234567890",
      "timestamp": "2025-11-26T12:34:56Z",
      "method": "GET",
      "url": "/api/data",
      "headers": {
        "User-Agent": "Mozilla/5.0",
        "Accept": "application/json"
      },
      "body": "",
      "remote_addr": "192.168.1.100",
      "content_type": "application/json"
    },
    "response": {
      "status_code": 200,
      "headers": {},
      "body": "{\"data\": \"test\"}",
      "timestamp": "2025-11-26T12:34:56Z"
    },
    "blocked": false,
    "reason": ""
  }
]
```

## 3. Research Workflow Examples

### Example 1: Detecting DDoS Patterns

```bash
# Start proxy with anomaly detection
./shieldcli run --proxy-to http://localhost:3000 --port 8080

# In another terminal, generate traffic
for i in {1..1000}; do curl http://localhost:8080/; done

# Check anomalies
./shieldcli anomaly report
```

### Example 2: Reproducible Attack Testing

```bash
# 1. Record normal traffic
./shieldcli run --proxy-to http://localhost:3000 --port 8080 --record-file normal.json

# 2. Inject attack traffic and record
# (Use a tool like curl or Burp Suite to send malicious requests)

# 3. Replay the traffic for analysis
./shieldcli replay play --input normal.json --target http://localhost:3000

# 4. Export for statistical analysis
./shieldcli replay export --input normal.json --output normal.csv
```

### Example 3: Statistical Analysis with External Tools

```bash
# Export traffic data
./shieldcli replay export --input traffic.json --output traffic.csv

# Analyze with Python/Pandas
python3 << 'EOF'
import pandas as pd

df = pd.read_csv('traffic.csv')
print(df.describe())
print(df[df['Blocked'] == True].groupby('Reason').size())
EOF
```

## 4. Data Export for Research

### CSV Export Format

```
ID,Timestamp,Method,URL,Status,Blocked,Reason
1234567890,2025-11-26T12:34:56Z,GET,/api/data,200,false,
1234567891,2025-11-26T12:34:57Z,POST,/api/login,403,true,Rule 1001: SQL Injection
```

### JSON Export Format

Full request/response details are available in the JSON format for detailed analysis.

## 5. Integration with Research Tools

### Pandas Analysis

```python
import pandas as pd
import json

# Load traffic data
with open('traffic.json') as f:
    data = json.load(f)

# Convert to DataFrame
records = []
for traffic in data:
    records.append({
        'method': traffic['request']['method'],
        'url': traffic['request']['url'],
        'status': traffic['response']['status_code'],
        'blocked': traffic['blocked'],
        'payload_size': len(traffic['request']['body']),
    })

df = pd.DataFrame(records)

# Statistical analysis
print(df.groupby('method')['status'].describe())
print(df[df['blocked']].groupby('method').size())
```

### Visualization

```python
import matplotlib.pyplot as plt

# Plot request distribution
df['method'].value_counts().plot(kind='bar')
plt.title('Request Distribution by Method')
plt.show()

# Plot blocked vs allowed
df['blocked'].value_counts().plot(kind='pie')
plt.title('Blocked vs Allowed Requests')
plt.show()
```

## 6. Performance Metrics

The replay feature provides detailed performance metrics:

- **Success Rate**: Percentage of successful replayed requests
- **Status Match Rate**: Percentage of responses with matching status codes
- **Body Match Rate**: Percentage of responses with matching bodies
- **Average Duration**: Average request duration during replay
- **Total Duration**: Total time for all replayed requests

## 7. Best Practices for Researchers

1. **Baseline Collection**: Always collect baseline traffic under normal conditions
2. **Controlled Testing**: Use dry-run mode to test rules without affecting traffic
3. **Data Preservation**: Export traffic data regularly for long-term analysis
4. **Reproducibility**: Use traffic replay to ensure reproducible testing
5. **Statistical Validation**: Use anomaly detection thresholds based on your baseline

## 8. Extending the Features

### Custom Anomaly Detectors

You can extend the anomaly detection module:

```go
detector := anomaly.NewAnomalyDetector(time.Hour)

// Customize thresholds
detector.requestRateThreshold = 500.0
detector.payloadSizeThreshold = 5 * 1024 * 1024
detector.entropyThreshold = 4.0
```

### Custom Filters

Filter recorded traffic for specific analysis:

```go
// Filter by method
getRequests := replayer.FilterRecordsByMethod("GET")

// Filter by status
successfulReplays := replayer.FilterResultsByStatus(200)

// Filter by match status
mismatchedReplays := replayer.FilterResultsByMatch(false, false)
```

## References

- OWASP: https://owasp.org/
- CRS (Core Rule Set): https://coreruleset.org/
- Statistical Anomaly Detection: https://en.wikipedia.org/wiki/Anomaly_detection
