# ShieldCLI Testing Guide

This document describes how to test ShieldCLI functionality.

## Prerequisites

1. Go 1.24+
2. A test application running on localhost:3000
3. (Optional) Google Gemini API key for AI testing

## Unit Tests

Run the test suite:
```bash
go test ./...
```

Run tests with verbose output:
```bash
go test -v ./...
```

Run tests with coverage:
```bash
go test -cover ./...
```

## Integration Tests

### 1. Start the Test Server

In one terminal:
```bash
go run test_server.go
```

The test server will listen on http://localhost:3000

### 2. Start ShieldCLI

In another terminal:
```bash
./shieldcli run --proxy-to http://localhost:3000 --port 8080 --log-file test.log
```

### 3. Test Normal Requests

These should pass through:
```bash
# Test GET request
curl -v http://localhost:8080/

# Test API endpoint
curl -v http://localhost:8080/api/data

# Test with query parameters
curl -v "http://localhost:8080/?name=John&age=30"
```

### 4. Test SQL Injection Detection

These should be blocked:
```bash
# SQL injection attempt 1
curl -v "http://localhost:8080/?id=1' OR '1'='1"

# SQL injection attempt 2
curl -v "http://localhost:8080/?id=1; DROP TABLE users--"

# SQL injection attempt 3
curl -X POST http://localhost:8080/api/data \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin' OR 1=1--&password=anything"
```

### 5. Test XSS Detection

These should be blocked:
```bash
# XSS attempt 1
curl -v "http://localhost:8080/?search=<script>alert('xss')</script>"

# XSS attempt 2
curl -v "http://localhost:8080/?comment=<img onerror=alert('xss')>"

# XSS attempt 3
curl -v "http://localhost:8080/?data=<svg onload=alert('xss')>"
```

### 6. Test Path Traversal Detection

These should be blocked:
```bash
# Path traversal attempt 1
curl -v "http://localhost:8080/../../etc/passwd"

# Path traversal attempt 2
curl -v "http://localhost:8080/..%2F..%2Fetc%2Fpasswd"
```

### 7. Test Command Injection Detection

These should be blocked:
```bash
# Command injection attempt 1
curl -v "http://localhost:8080/?cmd=ls;cat%20/etc/passwd"

# Command injection attempt 2
curl -v "http://localhost:8080/?file=test.txt|cat%20/etc/passwd"
```

### 8. Test User-Agent Blocking

These should be blocked:
```bash
# Suspicious user agent
curl -v -A "BadBot" http://localhost:8080/
```

## Testing Modes

### Dry-Run Mode

Test rules without blocking:
```bash
./shieldcli run --proxy-to http://localhost:3000 --port 8080 --dry-run
```

All requests should pass through, but malicious ones will be logged.

### Interactive Mode

Review requests before allowing them:
```bash
./shieldcli run --proxy-to http://localhost:3000 --port 8080 --interactive
```

When a suspicious request is detected, you'll be prompted to approve or deny.

## Testing Configuration

### Test with Custom Config

Create a test configuration:
```bash
./shieldcli config init --output test.yaml
```

Edit test.yaml to customize rules, then run:
```bash
./shieldcli run --config test.yaml
```

### Test Rule Management

List default rules:
```bash
./shieldcli rules list
```

Add a custom rule:
```bash
./shieldcli rules add \
  --id 9001 \
  --name "Test Rule" \
  --pattern "test" \
  --operator contains \
  --target REQUEST_BODY \
  --action block
```

## Testing AI Features

### Test Payload Analysis

Analyze a suspicious payload:
```bash
export GEMINI_API_KEY="your-api-key"
./shieldcli analyze payload "SELECT * FROM users WHERE id=1 OR 1=1--"
```

### Test Log Summarization

Create a test log file with some entries, then:
```bash
./shieldcli analyze log --log-file test.log
```

## Performance Testing

### Load Testing with Apache Bench

```bash
# 1000 requests with 10 concurrent connections
ab -n 1000 -c 10 http://localhost:8080/

# With a specific path
ab -n 1000 -c 10 http://localhost:8080/api/data
```

### Load Testing with wrk

```bash
# 4 threads, 100 connections, 30 second test
wrk -t4 -c100 -d30s http://localhost:8080/

# With custom script
wrk -t4 -c100 -d30s -s script.lua http://localhost:8080/
```

## Monitoring

### Check Logs

```bash
# View real-time logs
tail -f shieldcli.log

# Search for blocked requests
grep "blocked" shieldcli.log

# Count blocked requests by rule
grep "blocked" shieldcli.log | grep -o "Rule [0-9]*" | sort | uniq -c
```

### Monitor Resource Usage

```bash
# Watch memory and CPU usage
watch -n 1 'ps aux | grep shieldcli'

# Use top
top -p $(pgrep shieldcli)
```

## Troubleshooting Tests

### Requests not being blocked

1. Check if ShieldCLI is running: `ps aux | grep shieldcli`
2. Check the logs: `tail -f shieldcli.log`
3. Verify the proxy target is reachable: `curl http://localhost:3000`
4. Check if dry-run mode is enabled (it should be disabled for blocking)

### Test server not responding

1. Check if test server is running: `ps aux | grep test_server`
2. Check if port 3000 is in use: `lsof -i :3000`
3. Start the test server: `go run test_server.go`

### Gemini API errors

1. Verify API key: `echo $GEMINI_API_KEY`
2. Check API quota at https://console.cloud.google.com
3. Verify model name in config

## Continuous Integration

### GitHub Actions Example

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-go@v2
        with:
          go-version: 1.24
      - run: go test -v ./...
      - run: go build -o shieldcli ./cmd/main.go
```

## Test Coverage Goals

- **Minimum coverage**: 70%
- **Target coverage**: 85%+
- **Critical paths**: 100%

Run coverage report:
```bash
go test -cover ./... | grep coverage
```

Generate HTML coverage report:
```bash
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```
