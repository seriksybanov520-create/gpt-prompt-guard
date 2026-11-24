# Security Policy

## Scope & Defensive Intent

`gpt-prompt-guard` is a strictly **defensive** pre-filtering library for LLM API gateways and AI safety research.

- The repository intentionally contains **no raw offensive payloads, exploits, or live private threat-intelligence rulepacks**.
- Production operators should load private, rapidly evolving indicators at runtime via `WithRulepackJSON` rather than committing live operational signatures into public repositories.

## Reporting Security Issues

If you discover a bypass in the de-obfuscation pipeline, a parser/DoS vulnerability in JSON envelope scanning, or a false-positive regression affecting defensive security tooling:

1. **Do not** open a public issue containing active exploit payloads or weaponized prompts.
2. Report privately via GitHub Security Advisories on this repository with a minimal synthetic reproduction case (and expected vs. observed `Result`).
3. Include the Go version and input size if reporting a performance or algorithmic-complexity issue.
