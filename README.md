# ShieldCLI - Terminal-First Web Application Firewall

[![CI](https://github.com/shieldcli/shieldcli/actions/workflows/ci.yml/badge.svg)](https://github.com/shieldcli/shieldcli/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/github/go-mod/go-version/shieldcli/shieldcli?style=for-the-badge&label=Go)](go.mod)
[![License](https://img.shields.io/github/license/shieldcli/shieldcli?style=for-the-badge)](LICENSE)
[![CLA](https://img.shields.io/badge/CLA-Required-blue?style=for-the-badge)](#contributor-license-agreement-cla)

[![Architecture Diagram](https://img.shields.io/badge/Architecture-Diagram-blue?style=for-the-badge&logo=mermaid)](https://files.manuscdn.com/user_upload_by_module/session_file/310419663030496762/RLCcCukNJWvlpecY.png)

ShieldCLI is a lightweight, terminal-first Web Application Firewall (WAF) that can be deployed on edge servers, developer machines, or containers to protect HTTP services in real time. It features real-time traffic interception, rule-based blocking with OWASP-style attack detection, and AI-powered threat analysis using Google's Gemini API.

## Features

### 🛡️ Core WAF Engine

- **Real-time traffic interception**: Acts as a reverse proxy (e.g., on localhost:8080 → forwards to your app on localhost:3000)

- **Rule-based blocking**: Detects and blocks common attacks including:
  - SQL Injection (SQLi)
  - Cross-Site Scripting (XSS)
  - Path Traversal
  - Command Injection
  - Suspicious User-Agents
  - High-entropy payloads (potential obfuscation/encoding)

- **Custom rules**: Define your own security rules via YAML configuration

- **Logging & Alerts**: Terminal logs with color-coded severity, export to file

### 🤖 AI-Powered Threat Analysis

- **Gemini Integration**: Forward suspicious payloads to Google's Gemini API for advanced analysis

- **Automated rule suggestion**: Get recommendations for new WAF rules based on detected attack patterns

- **Incident summarization**: Generate human-readable summaries of attack trends

### 👨‍💻 Developer-Friendly UX

- **One-command startup**: `shieldcli run --proxy-to http://localhost:3000 --port 8080`

- **Interactive mode**: Review and approve/deny suspicious requests in real time

- **Dry-run mode**: Test rules without blocking traffic

- **Configuration management**: Initialize and export configurations for different environments

## Installation

### From Source

```bash
git clone https://github.com/shieldcli/shieldcli.git
cd shieldcli
go build -o shieldcli ./cmd/main.go
```

### Requirements

- Go 1.24+ (for Gemini SDK support )

- Google Gemini API key (optional, for AI features)

## Quick Start

### 1. Initialize Configuration

```bash
./shieldcli config init --output shieldcli.yaml
```

### 2. Start the WAF Proxy

```bash
./shieldcli run --proxy-to http://localhost:3000 --port 8080
```

Your application is now protected! All traffic to `http://localhost:8080` will be filtered through ShieldCLI before reaching your app on port 3000.

### 3. Test with a Malicious Request

```bash
# This will be blocked (SQL injection attempt )
curl "http://localhost:8080/?id=1' OR '1'='1"

# This will pass through
curl "http://localhost:8080/api/data"
```

## Usage

### Run the WAF Proxy

```bash
./shieldcli run \
  --proxy-to http://localhost:3000 \
  --port 8080 \
  --dry-run \
  --log-file ./waf.log
```

**Flags:**

- `--proxy-to`: Target application URL (required )

- `--port`: Local port to listen on (default: 8080)

- `--dry-run`: Log but don't block requests

- `--interactive`: Pause and ask for approval on suspicious requests

- `--gemini-key`: Google Gemini API key (or set `GEMINI_API_KEY` env var)

- `--log-file`: Path to export WAF logs

- `--config`: Path to configuration file

### Analyze a Payload

```bash
export GEMINI_API_KEY="your-api-key"
./shieldcli analyze payload "SELECT * FROM users WHERE id=1 OR 1=1--"
```

### Summarize Attack Trends

```bash
./shieldcli analyze log --log-file ./waf.log
```

### Manage Rules

```bash
# List all active rules
./shieldcli rules list

# Add a custom rule
./shieldcli rules add \
  --id 9001 \
  --name "Block Specific IP" \
  --pattern "192.168.1.100" \
  --operator equals \
  --target REMOTE_ADDR \
  --action block
```

### Configuration Management

```bash
# Initialize a new config file
./shieldcli config init --output shieldcli.yaml

# Export config for Docker
./shieldcli config export --format dockerfile --output Dockerfile

# Export config for Terraform
./shieldcli config export --format terraform --output main.tf
```

## Configuration File

Create a `shieldcli.yaml` file to customize ShieldCLI:

```yaml
# Proxy settings
proxy:
  listen_port: 8080
  target_url: "http://localhost:3000"
  timeout: 30

# WAF Engine Settings
waf:
  default_action: "block"
  enabled_rules:
    - 1001  # SQL Injection
    - 1002  # XSS
    - 1003  # Path Traversal
    - 1004  # Command Injection
    - 1005  # Suspicious User-Agent
    - 1006  # High Entropy Payload

# Logging
logging:
  terminal_enabled: true
  terminal_level: "info"
  file_path: "./shieldcli.log"
  file_format: "text"

# Gemini AI Integration
gemini:
  api_key: "YOUR_API_KEY"
  model: "gemini-2.5-flash"
  enabled: true
  analysis_threshold: 5

# Custom Rules
custom_rules:
  - id: 9001
    name: "Block Specific IP"
    phase: "request_headers"
    operator: "equals"
    pattern: "192.168.1.100"
    target: "REMOTE_ADDR"
    action: "block"
    severity: "high"
    enabled: true
```

## Default Rules

ShieldCLI comes with 6 built-in security rules:

| ID | Name | Detection | Severity |
| --- | --- | --- | --- |
| 1001 | SQL Injection | Detects common SQL injection patterns | Critical |
| 1002 | Cross-Site Scripting (XSS ) | Detects XSS attack vectors | Critical |
| 1003 | Path Traversal | Detects directory traversal attempts | High |
| 1004 | Command Injection | Detects shell command injection | Critical |
| 1005 | Suspicious User-Agent | Blocks known malicious user agents | Medium |
| 1006 | High Entropy Payload | Detects obfuscated/encoded payloads | Medium |

## Advanced Features

### Interactive Mode

Pause and review suspicious requests before allowing them through:

```bash
./shieldcli run --proxy-to http://localhost:3000 --port 8080 --interactive
```

When a suspicious request is detected, you'll be prompted:

```
[INTERACTIVE]: # "Suspicious request detected: Rule 1001: SQL Injection - Common Patterns"
[A]pprove or [D]eny? (a/d ): 
```

### Dry-Run Mode

Test your rules without blocking traffic:

```bash
./shieldcli run --proxy-to http://localhost:3000 --port 8080 --dry-run
```

All rules are evaluated and logged, but requests are not blocked.

### AI-Powered Analysis

Enable Gemini integration for advanced threat detection:

```bash
export GEMINI_API_KEY="your-api-key"
./shieldcli run --proxy-to http://localhost:3000 --port 8080 --gemini-key $GEMINI_API_KEY
```

## Deployment

### Docker

```bash
# Build the Docker image
docker build -t shieldcli:latest .

# Run as a container
docker run -p 8080:8080 \
  -e PROXY_TO=http://localhost:3000 \
  -e GEMINI_API_KEY=your-api-key \
  -v $(pwd )/shieldcli.yaml:/etc/shieldcli/shieldcli.yaml \
  shieldcli:latest
```

### Kubernetes

```bash
kubectl apply -f shieldcli-deployment.yaml
```

![ShieldCLI Architecture](https://files.manuscdn.com/user_upload_by_module/session_file/310419663030496762/RLCcCukNJWvlpecY.png)

## Architecture

ShieldCLI is built with a modular architecture:

- **Proxy Engine**: Go's `net/http` for high-performance reverse proxying

- **WAF Engine**: Custom rule engine with pattern matching and attack detection

- **Gemini Integration**: Google's official Gemini SDK for AI analysis

- **Configuration**: YAML-based configuration with environment variable support

- **Logging**: Color-coded terminal output with file export

## Performance

ShieldCLI is designed for low-latency, high-throughput scenarios:

- **Latency**: <5ms per request (typical )

- **Throughput**: 10,000+ requests/second (typical)

- **Memory**: ~50MB baseline

- **CPU**: Minimal overhead for rule matching

## Security Considerations



1. **Network**: Deploy ShieldCLI on the same network as your application for best performance.

## Troubleshooting

### Requests are being blocked unexpectedly

1. Check the logs: `tail -f shieldcli.log`

1. Enable dry-run mode to test without blocking

1. Use interactive mode to review blocked requests

### Gemini API errors

1. Verify your API key is set: `echo $GEMINI_API_KEY`

1. Check your API quota at [https://console.cloud.google.com](https://console.cloud.google.com)

1. Ensure the model name is correct in your config

### Performance issues

1. Check the proxy target is reachable

1. Monitor CPU and memory usage

1. Consider disabling AI analysis if it's causing slowdowns

## Contributing

Contributions are welcome! Please submit pull requests or issues on GitHub.

### Contributor License Agreement (CLA)

Before we can merge your pull request, you may be asked to sign a Contributor License Agreement (CLA). This helps protect both you and the project maintainers.

You will receive an automated comment on your pull request with a link to the CLA and instructions on how to sign it.

## License

MIT License - see LICENSE file for details

## Support

For issues, questions, or feature requests, please open an issue on GitHub or visit the documentation at [https://shieldcli.dev](https://shieldcli.dev)

---

**Made with ❤️ for developers who care about security**

