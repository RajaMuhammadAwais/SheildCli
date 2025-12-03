# ShieldCLI Project Roadmap and Milestones

The development of ShieldCLI will be structured into three major phases, each culminating in a significant, testable milestone. This phased approach ensures a stable foundation before integrating the more complex AI features.

## Phase 1: Core WAF Engine (MVP)

**Goal:** Establish a stable, high-performance reverse proxy that can load and enforce basic WAF rules.

| Milestone | Description | Key Features |
| :--- | :--- | :--- |
| **M1.1: Basic Proxy** | Implement the core reverse proxy functionality using Go's `net/http/httputil`. | Single command startup: `shieldcli --proxy-to <target> --port <listen>` |
| **M1.2: Coraza Integration** | Integrate the `corazawaf/coraza` library into the request lifecycle. | Load a minimal WAF configuration file. |
| **M1.3: Rule Enforcement** | Implement the ability to load and enforce a small, custom rule set (e.g., block "BadBot"). | Terminal logging of blocked requests. |
| **M1.4: Dry-Run Mode** | Implement the `--dry-run` flag, allowing WAF rules to be evaluated without blocking traffic. | |

**Deliverable:** A functional, rule-based WAF CLI that can proxy traffic and log basic security events.

## Phase 2: AI Integration and Developer UX

**Goal:** Integrate the Gemini API for threat analysis and implement the core developer-friendly features.

| Milestone | Description | Key Features |
| :--- | :--- | :--- |
| **M2.1: Gemini CLI Utility** | Implement the `shieldcli analyze payload` subcommand using the Go Gemini SDK. | Successful API call and response parsing. |
| **M2.2: AI-Triggered Analysis** | Implement the logic to forward suspicious payloads (based on WAF anomaly score) to the Gemini API. | Gemini provides a "malicious/not malicious" verdict in the terminal log. |
| **M2.3: Interactive Mode** | Implement the `--interactive` flag, pausing traffic flow for user review of suspicious requests. | User input (A/D) in the terminal to Approve or Deny a request. |
| **M2.4: Rule Suggestion** | Implement the logic for Gemini to suggest a new WAF rule based on a detected attack pattern. | `shieldcli rules add` command is populated with the suggested rule. |

**Deliverable:** A WAF CLI with integrated AI-powered threat analysis and a highly interactive developer experience.

## Phase 3: Extensibility and Production Readiness

**Goal:** Finalize configuration, logging, and extensibility features for deployment in various environments.

| Milestone | Description | Key Features |
| :--- | :--- | :--- |
| **M3.1: Full CRS Support** | Configure Coraza to correctly load and utilize the full OWASP Core Rule Set. | Robust testing against common attack vectors (SQLi, XSS). |
| **M3.2: Advanced Logging** | Implement structured logging (JSON) and the `--log-file` feature for SIEM integration. | Color-coded severity in terminal logs. |
| **M3.3: Configuration Export** | Implement the `shieldcli config export` subcommand. | Export WAF configuration as a Terraform resource or Dockerfile snippet. |
| **M3.4: Incident Summarization** | Implement the `shieldcli analyze log` subcommand. | Use Gemini to summarize attack trends from a log file. |

**Deliverable:** A production-ready, highly configurable, and extensible WAF CLI tool.

## Summary of Key Features by Phase

| Feature | Phase 1 | Phase 2 | Phase 3 |
| :--- | :--- | :--- | :--- |
| **Reverse Proxy** | ✅ Basic | ✅ Stable | ✅ Production |
| **Custom Rule Blocking** | ✅ Basic | ✅ Enhanced | ✅ Full CRS |
| **Terminal Logging** | ✅ Basic | ✅ Interactive | ✅ Advanced/SIEM |
| **Gemini AI Analysis** | ❌ | ✅ Real-time | ✅ Summarization |
| **Interactive Mode** | ❌ | ✅ Implemented | ✅ Refined |
| **Config Export** | ❌ | ❌ | ✅ Terraform/Docker |
| **Dry-Run Mode** | ✅ Implemented | ✅ Refined | ✅ Stable |
| **Automated Rule Suggestion** | ❌ | ✅ Implemented | ✅ Refined |

This roadmap provides a clear path from a minimal viable product to a fully-featured, AI-enhanced WAF solution.
