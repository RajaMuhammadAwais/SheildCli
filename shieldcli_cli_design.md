# ShieldCLI Command-Line Interface (CLI) and Configuration Design

The design for ShieldCLI prioritizes a **terminal-first, developer-friendly experience** with clear, concise commands and flexible configuration.

## 1. CLI Command Structure

The CLI will be structured around a main `shieldcli` command with a primary `run` mode (default) and several utility subcommands.

### A. Main `run` Command (Default)

The primary use case is running the WAF as a reverse proxy. This will be the default action when no subcommand is provided.

| Flag | Type | Description | Example Value | Required |
| :--- | :--- | :--- | :--- | :--- |
| `--proxy-to` | URL | The target application URL to forward traffic to. | `http://localhost:3000` | Yes |
| `--port` | Integer | The local port on which ShieldCLI will listen. | `8080` | Yes |
| `--config` | File Path | Path to the main configuration file (YAML/TOML). | `./shieldcli.yaml` | No (Default: `./shieldcli.yaml`) |
| `--dry-run` | Boolean | Activates dry-run mode. Requests are logged and analyzed, but no blocking occurs. | `true` | No |
| `--interactive` | Boolean | Activates interactive mode. User must approve/deny suspicious requests in the terminal. | `true` | No |
| `--gemini-key` | String | Your Google Gemini API key. Can also be set via `GEMINI_API_KEY` environment variable. | `YOUR_API_KEY` | No |
| `--log-file` | File Path | Path to export detailed WAF logs. | `./waf.log` | No |

**Example Usage:**

```bash
# Standard run mode
shieldcli --proxy-to http://localhost:3000 --port 8080

# Dry-run mode with explicit config file
shieldcli --proxy-to http://localhost:3000 --port 8080 --dry-run --config /etc/shieldcli/prod.yaml

# Interactive mode (for developer testing)
shieldcli --proxy-to http://localhost:3000 --port 8080 --interactive
```

### B. Utility Subcommands

| Subcommand | Description | Flags/Arguments |
| :--- | :--- | :--- |
| `rules` | Manages custom WAF rules. | |
| `rules add` | Adds a new custom rule from a template or file. | `--name`, `--pattern`, `--action` |
| `rules list` | Lists all active custom rules. | |
| `config` | Manages configuration files. | |
| `config init` | Generates a boilerplate `shieldcli.yaml` file. | |
| `config export` | Exports the current WAF configuration to a different format (e.g., Terraform, Dockerfile). | `--format [terraform, dockerfile]` |
| `analyze` | Utility for one-off AI analysis of a payload. | |
| `analyze payload` | Sends a raw payload string to Gemini for analysis. | `<payload_string>` |
| `analyze log` | Summarizes recent attack trends from a log file. | `--log-file`, `--time-range` |

**Example Usage:**

```bash
# Initialize a new configuration file
shieldcli config init

# Export configuration for a Docker environment
shieldcli config export --format dockerfile

# Analyze a suspicious string directly
shieldcli analyze payload "SELECT * FROM users WHERE id=1 OR 1=1--"
```

## 2. Configuration File Structure (YAML)

The primary configuration will be managed via a YAML file (e.g., `shieldcli.yaml`). This file will define global settings, logging preferences, and custom WAF rules.

```yaml
# shieldcli.yaml

# Global Proxy Settings
proxy:
  # The port ShieldCLI listens on (can be overridden by --port flag)
  listen_port: 8080
  # The target application to forward to (can be overridden by --proxy-to flag)
  target_url: "http://localhost:3000"
  # Timeout for forwarding requests (in seconds)
  timeout: 30

# WAF Engine Settings
waf:
  # Path to the OWASP CRS rules (e.g., /etc/coraza/crs-v3.3)
  crs_path: "/usr/share/coraza/crs"
  # Default action when a rule is triggered: 'block', 'log', 'dry-run'
  default_action: "block"
  # Score threshold for blocking a request (Coraza's anomaly scoring)
  anomaly_threshold: 5

# Logging and Reporting
logging:
  # Enable/disable terminal logging
  terminal_enabled: true
  # Log level for terminal output: 'info', 'warn', 'error', 'debug'
  terminal_level: "info"
  # File path for detailed logs (can be overridden by --log-file flag)
  file_path: "./shieldcli.log"
  # Format for log file: 'json', 'text'
  file_format: "json"

# Gemini AI Integration Settings
gemini:
  # API Key (optional, can be set via GEMINI_API_KEY env var)
  # api_key: "YOUR_API_KEY"
  # Model to use for threat analysis
  model: "gemini-2.5-flash"
  # Threshold for triggering AI analysis (e.g., if WAF score > 3)
  analysis_threshold: 3

# Custom WAF Rules
# These rules are loaded in addition to the OWASP CRS
custom_rules:
  - id: 900001
    name: "Block BadBot User-Agent"
    # Coraza/ModSecurity rule syntax
    rule: "SecRule REQUEST_HEADERS:User-Agent \"BadBot\" \"id:900001,phase:1,log,deny,msg:'BadBot User-Agent Blocked'\""
  - id: 900002
    name: "High-Entropy Payload AI Check"
    # A special rule to trigger AI analysis for high-entropy strings
    rule: "SecRule REQUEST_BODY|REQUEST_URI \"@detectHighEntropy\" \"id:900002,phase:2,log,pass,setvar:tx.ai_check=1,msg:'High Entropy Detected, Forwarding to AI'\""
```

## 3. Custom WAF Rule Structure

For simplicity and compatibility with the `coraza` engine, custom rules will be defined using the **ModSecurity Rule Language syntax** within the configuration file. This allows developers familiar with traditional WAFs to easily write and integrate their own rules.

**Example Custom Rule (YAML):**

```yaml
  - id: 900003
    name: "Block Specific IP Range"
    rule: "SecRule REMOTE_ADDR \"@ipMatch 192.168.1.0/24\" \"id:900003,phase:1,log,deny,msg:'Internal IP Range Blocked'\""
```

This design ensures that ShieldCLI is powerful and extensible while maintaining the simple, single-command startup experience requested by the user. The separation of configuration into a file allows for easy management of complex rule sets and persistent settings.
