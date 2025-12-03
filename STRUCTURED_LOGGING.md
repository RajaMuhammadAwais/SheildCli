# Structured Logging for SIEM/Data Analysis Integration

## Overview

ShieldCLI now includes a powerful structured logging module that enables security researchers and analysts to export WAF events in standardized formats (JSON and CSV) for integration with SIEM systems, data analysis tools, and threat intelligence platforms.

## Features

### 1. **Multiple Export Formats**

- **JSON Format**: Complete event details with nested structures for complex analysis
- **CSV Format**: Tabular format for Excel, Pandas, R, and other data analysis tools
- **Real-time Logging**: Events are logged as they occur with color-coded severity

### 2. **Rich Event Metadata**

Each logged event includes:

```json
{
  "timestamp": "2025-12-01T10:30:45Z",
  "event_id": "evt-12345",
  "event_type": "blocked",
  "severity": "high",
  "source_ip": "192.168.1.100",
  "destination_ip": "10.0.0.1",
  "method": "POST",
  "url": "/api/login",
  "user_agent": "Mozilla/5.0",
  "request_size": 1024,
  "response_size": 512,
  "status_code": 403,
  "rule_id": "1001",
  "rule_name": "SQL Injection",
  "rule_action": "block",
  "blocked": true,
  "reason": "SQL injection pattern detected",
  "payload_entropy": 4.2,
  "response_time_ms": 15,
  "headers": {
    "Content-Type": "application/json",
    "Authorization": "Bearer ..."
  },
  "query_params": {
    "id": "1' OR '1'='1"
  },
  "metadata": {
    "attack_vector": "query_parameter",
    "confidence": 0.95
  }
}
```

### 3. **Filtering and Analysis**

Query events by:
- Severity level (critical, high, medium, low)
- Blocked status
- Rule ID
- Time range
- Source IP
- HTTP method

### 4. **Statistics and Reporting**

Generate statistics including:
- Total events processed
- Block rate percentage
- Events by severity
- Events by rule
- Top attacking IPs
- Top targeted URLs

## Usage

### Initialize Structured Logger

```go
import "github.com/shieldcli/shieldcli/pkg/logging"

// Create logger with JSON and CSV exports
logger, err := logging.NewStructuredLogger(
    "events.json",  // JSON log file
    "events.csv",   // CSV log file
    10000,          // Max events in memory
)
if err != nil {
    log.Fatal(err)
}
defer logger.Close()
```

### Log an Event

```go
event := logging.StructuredEvent{
    EventID:      "evt-001",
    EventType:    "blocked",
    Severity:     "high",
    SourceIP:     "192.168.1.100",
    Method:       "POST",
    URL:          "/api/login",
    UserAgent:    "Mozilla/5.0",
    RequestSize:  1024,
    StatusCode:   403,
    RuleID:       "1001",
    RuleName:     "SQL Injection",
    RuleAction:   "block",
    Blocked:      true,
    Reason:       "SQL injection pattern detected",
    PayloadEntropy: 4.2,
    ResponseTime: 15,
}

logger.LogEvent(event)
```

### Export Data

```go
// Export to JSON
logger.ExportJSON("export.json")

// Export to CSV
logger.ExportCSV("export.csv")
```

### Query Events

```go
// Get all blocked events
blockedEvents := logger.GetBlockedEvents()

// Get events by severity
criticalEvents := logger.GetEventsBySeverity("critical")

// Get events by rule
sqlInjectionEvents := logger.GetEventsByRule("1001")
```

### Get Statistics

```go
stats := logger.GetStatistics()
fmt.Printf("Total Events: %v\n", stats["total_events"])
fmt.Printf("Block Rate: %.2f%%\n", stats["block_rate"])
fmt.Printf("Severity Count: %v\n", stats["severity_count"])
```

## Integration with SIEM Systems

### Splunk Integration

```bash
# Configure Splunk to ingest JSON logs
# In inputs.conf:
[monitor:///var/log/shieldcli/events.json]
sourcetype = shieldcli:json
index = security
```

### ELK Stack Integration

```bash
# Use Filebeat to ship logs to Elasticsearch
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/shieldcli/events.json
  json.message_key: message
  json.keys_under_root: true

output.elasticsearch:
  hosts: ["localhost:9200"]
  index: "shieldcli-%{+yyyy.MM.dd}"
```

## Data Analysis with Python/Pandas

```python
import pandas as pd
import json

# Load JSON logs
with open('events.json') as f:
    events = [json.loads(line) for line in f]

df = pd.DataFrame(events)

# Analyze blocked events
blocked = df[df['blocked'] == True]
print(f"Block Rate: {len(blocked) / len(df) * 100:.2f}%")

# Top attacking IPs
print(df[df['blocked']]['source_ip'].value_counts().head(10))

# Events by rule
print(df[df['blocked']].groupby('rule_name').size())

# Time-based analysis
df['timestamp'] = pd.to_datetime(df['timestamp'])
df.set_index('timestamp').resample('1H').size().plot()
```

## Data Analysis with R

```r
library(jsonlite)
library(dplyr)

# Load JSON logs
events <- stream_in(file("events.json"))

# Convert to data frame
df <- as.data.frame(events)

# Analyze blocked events
blocked <- df %>% filter(blocked == TRUE)
cat(sprintf("Block Rate: %.2f%%\n", nrow(blocked) / nrow(df) * 100))

# Top attacking IPs
df %>% 
  filter(blocked == TRUE) %>%
  group_by(source_ip) %>%
  summarise(count = n()) %>%
  arrange(desc(count)) %>%
  head(10)

# Events by rule
df %>%
  filter(blocked == TRUE) %>%
  group_by(rule_name) %>%
  summarise(count = n())
```

## CSV Format

The CSV export includes the following columns:

| Column | Description |
|--------|-------------|
| Timestamp | Event timestamp (RFC3339) |
| EventID | Unique event identifier |
| EventType | Type of event (request, blocked, anomaly) |
| Severity | Event severity (low, medium, high, critical) |
| SourceIP | Source IP address |
| Method | HTTP method (GET, POST, etc.) |
| URL | Request URL |
| StatusCode | HTTP response status code |
| Blocked | Whether the request was blocked |
| RuleID | ID of the rule that triggered |
| RuleName | Name of the rule |
| Reason | Reason for blocking (if blocked) |

## Performance Considerations

- **Memory Usage**: Events are stored in memory (configurable max size)
- **Disk I/O**: JSON and CSV writes are buffered for performance
- **Thread Safety**: All operations are thread-safe with mutex protection
- **Scalability**: Tested with 100,000+ events per minute

## Best Practices

1. **Regular Exports**: Export logs regularly to prevent memory overflow
2. **Rotation**: Implement log rotation to manage disk space
3. **Retention**: Define retention policies based on compliance requirements
4. **Encryption**: Encrypt logs in transit and at rest
5. **Backup**: Maintain backups of critical logs
6. **Monitoring**: Monitor the WAF itself for anomalies

## Troubleshooting

### High Memory Usage

If memory usage is high, reduce the `maxEvents` parameter or export logs more frequently.

### Slow Performance

If performance degrades, consider:
- Disabling real-time stdout logging
- Increasing the export interval
- Using CSV instead of JSON for better performance

### Missing Events

Ensure that:
- Log files have write permissions
- Disk space is available
- The logger is not closed prematurely

## Future Enhancements

- Parquet format support for big data analysis
- Real-time streaming to Kafka/Pub-Sub
- Automatic log rotation
- Compression support
- Encryption at rest

## References

- [OWASP WAF Testing](https://owasp.org/www-project-web-security-testing-guide/)
- [Splunk Data Ingestion](https://docs.splunk.com/Documentation/Splunk/latest/Data/Monitorfiles)
- [ELK Stack Logging](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-log.html)
- [Pandas Data Analysis](https://pandas.pydata.org/docs/)
