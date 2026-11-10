# Changelog

All notable changes to Penteos are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-10

The first public release: the AI pentest workbench. Recon to report in one place, with an agent
that stays in scope and masks your client's data before the AI reads it.

### The three rules

- **Client data masked before the AI reads it.** Names, e-mails, national IDs (AR, BR, CL, MX,
  ES, US, by their check digits), cards, bank accounts, tokens, keys, birth dates and clinical
  notes become stable pseudonyms at the source; the real value goes back only on the way to the
  target and in the report. `pnpm privacy:measure` serves 240 synthetic values in 17 kinds of data
  as JSON, database rows, logs, HTML, CSV and free text: none reach the model. What it does not
  catch yet is in [SECURITY.md](SECURITY.md#known-limits).
- **Scope enforced by the core.** Every tool run, request, browser page and agent action is
  checked against hosts, ports and time windows, including internal hostnames such as
  `dc01.corp.local`; anything above the risk ceiling waits for the operator's approval.
- **No proof, no finding.** Findings cite the exact lines of raw output, a separate verifier tries
  to reproduce them, and only the operator approves what reaches the report.

### The workbench

- **The Maestro**, an agent that plans by phase, runs real tools and drafts findings, with an
  autopilot that keeps working inside the rules and collects its decisions in one inbox.
- **Models:** Sign in with ChatGPT to run on your ChatGPT plan, DeepSeek, OpenAI and Anthropic
  APIs, any OpenAI-compatible endpoint, local models (Ollama, LM Studio, llama.cpp, vLLM), and the
  Claude Code and Codex CLIs you installed. Any MCP client can drive Penteos as an agent.
- **Intercepting proxy and an in-scope browser**, with history, interception, rules, a fuzzer and
  WebSockets.
- **Tools without root:** a catalog of security tools installed in your user folder, each pinned
  to its SHA-256, with Penteos's own fallbacks when one is missing.
- **CVE intelligence by version**, with what it would take to confirm each match.
- **Reports** in Word, PDF, HTML and Markdown, technical and executive, with versions and your
  template.
- **Plugins**, declarative or code, with permissions and an isolated mode.
- **Team server (experimental):** the same core, self-hosted, with operators and roles; on the
  network it requires TLS.

### Packages

- AppImage, `.deb`, `.rpm` and `.tar.gz` for x86_64 and arm64, built against glibc 2.28 so they
  run on Debian 10, Ubuntu 20.04, RHEL 8 and newer.
- A one-line installer that picks the right package and checks it against `SHA256SUMS`.
- Every release is built and installed on clean distributions by the public release workflow
  before it is published.
