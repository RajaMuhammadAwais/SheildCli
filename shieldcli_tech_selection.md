# ShieldCLI Core Technology Selection and Rationale

The ShieldCLI project requires a technology stack that balances **high performance** for real-time traffic processing with **developer-friendly tooling** for rapid development and deployment. Based on the initial research, the following core technologies are selected:

## 1. Programming Language: Go (Golang)

| Criterion | Go Rationale | Rust Comparison |
| :--- | :--- | :--- |
| **WAF Integration** | **Strong:** The existence of `corazawaf/coraza` provides a production-ready, ModSecurity-compatible WAF engine, which is critical for the core **OWASP CRS support**. | Requires building WAF logic from scratch or integrating a less mature library. |
| **Development Speed** | **High:** Simpler syntax, built-in garbage collection, and a mature standard library for networking accelerate development. | Steeper learning curve and focus on memory safety can slow down initial prototyping. |
| **Performance** | **Excellent:** Go's concurrency model (goroutines) and efficient networking stack are highly suitable for I/O-bound tasks like a reverse proxy. | Superior raw performance, but Go is "fast enough" for the target use case (developer machine/edge server). |
| **CLI Tooling** | **Excellent:** Go is the de facto standard for modern CLI tools (e.g., Docker, Kubernetes, Terraform), offering easy cross-compilation and single-binary distribution. | Also excellent, but Go has a slight edge in the existing ecosystem of CLI frameworks. |

**Conclusion:** Go provides the best balance of performance, development velocity, and immediate access to a robust WAF library (`coraza`), making it the ideal choice for the initial implementation of ShieldCLI.

## 2. Reverse Proxy Engine: Go's `net/http/httputil.ReverseProxy` (with `fasthttp` consideration)

The initial proxy will be built using Go's standard library `net/http/httputil.ReverseProxy` for simplicity and reliability. If performance profiling later indicates a bottleneck, a switch to a more specialized, high-performance library like **`valyala/fasthttp`** will be considered.

## 3. WAF Engine: `corazawaf/coraza`

This library is a **ModSecurity-compatible WAF engine written in Go**. It is the most critical component for fulfilling the **OWASP Core Rule Set (CRS) support** requirement.

*   **Key Benefit:** It allows ShieldCLI to load and process the official OWASP CRS rules directly, providing immediate, industry-standard protection.
*   **Integration:** The library is designed to be embedded, allowing us to hook into the request/response lifecycle of our reverse proxy to perform WAF checks.

## 4. Gemini Integration: Google's Official Go SDK

The Gemini AI integration will be handled using the **official Google Gemini Go SDK**. This ensures a stable, supported, and idiomatic way to implement the AI-powered features:

*   **AI-powered anomaly detection:** Send suspicious payloads to the Gemini API for analysis.
*   **Automated rule suggestion:** Use Gemini's output to format suggested WAF rules.
*   **Incident summarization:** Generate human-readable summaries of attack trends.

This technology stack provides a solid foundation for building a high-performance, feature-rich, and maintainable WAF CLI tool.
