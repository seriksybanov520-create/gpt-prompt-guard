# Deterministic Sub-Millisecond Pre-Filtering for Frontier LLM Gateways

## 1. Motivation

Safety enforcement for frontier models relies primarily on model-level alignment and secondary neural classifiers. In high-throughput API gateways and agentic proxy surfaces, however, relying exclusively on neural classifiers creates three operational gaps:

1. **Latency and cost at scale:** Running an auxiliary LLM classifier on every multi-hundred-kilobyte coding or multimodal request adds tens to hundreds of milliseconds of tail latency and non-trivial compute cost.
2. **Surface-level and structural evasion:** Modern jailbreak kits routinely evade naive keyword filters and occasionally degrade neural monitors using zero-width steganography, Unicode Tags (`U+E0000..U+E007F`), mixed-script homoglyphs, keyboard-layout substitution (e.g., Cyrillic typed on EN-QWERTY), Classical Chinese (Wenyan / CC-BOS transfer), and structural JSON spoofing such as injected trailing `role: "tool"` turns.
3. **False positives on defensive traffic:** Security engineers, red-team researchers, and developers reviewing moderation code routinely discuss security terminology (`exploit`, `kernel`, `jailbreak`, `system prompt`) in benign contexts.

`gpt-prompt-guard` implements a **deterministic, zero-GPU, inspection-only pre-filter** designed to run *in front of* neural classifiers and model alignment—eliminating known high-confidence attacks and obfuscated smuggling vectors in microseconds while maintaining strict zero-false-positive discipline on benign developer and security-research traffic.

---

## 2. Threat Taxonomy Addressed

The public research rulepack and structural detectors in `gpt-prompt-guard` model eight recurring adversarial classes observed against frontier reasoning and coding models:

| Class | Mechanism | Deterministic Mitigation |
| --- | --- | --- |
| **Instruction Override & Roleplay** | Direct hierarchy overrides paired with unrestricted persona unlocks (EN/RU/UK). | Multi-category scoring gate in `ModeLight`; single weak phrases never block alone. |
| **Verbatim Prompt Extraction** | Multi-clause directives requesting exact system prompt or tool-definition dumps (EN/RU/UK/ZH). | Window-bounded composite matching ($\le 320$ runes) that never crosses JSON turn separators (`═══`). |
| **Single-Boundary Reduction & Classical Chinese (Wenyan / CC-BOS)** | Framing an entire session as a private workspace with exactly one prohibited boundary (e.g., CSAM), neutralizing target names ("vendor is an interface, not a victim"), suppressing refusal taxonomy, and splitting malicious logic across single-component turns—often rendered in Classical Chinese (Wenyan, cf. CC-BOS ICLR 2026). | Multi-directive composite rules + Traditional$\to$Simplified Han folding + adjacent-Han space compaction, explicitly tested against benign Classical Chinese prose, benign Wenyan `AGENTS.md` files, and academic CC-BOS paper summaries. |
| **Synthetic Fixture Relabeling** | Three-part behavioral lock: treat refusals as failing answers, silently relabel real targets as synthetic local fixtures, and force immediate placeholder templates. | Three-category structural requirement (`refusal_fallback_suppression` + `synthetic_fixture_relabeling` + `forced_response_template`/`roleplay_jailbreak`). |
| **Workspace Policy Spoofing** | Forged "operating policy" / "content guidelines" blocks claiming platform safety cues are "training residue" or injected noise. | Multi-phrase load-bearing scaffolding composites. |
| **Transcript Continuation Bypass** | Supplying a fictional transcript containing an earlier assistant refusal and instructing the model to continue as the next speaker without copying the refusal. | Composite detection of transcript-completion + quoted-refusal continuation directives. |
| **Multi-Layer Obfuscation & Steganography** | Zero-width steganography envelopes (`U+2063 U+2063` ... `U+2064 U+2064`), Unicode Tags, Cyrillic/Greek homoglyphs, leetspeak, typoglycemia, EN-QWERTY$\to$RU/UK layout substitution, ROT13, and 76-column line-wrapped Base64/Hex up to 128 KiB. | Bounded inspection-only variant expansion with strict byte budgets (256 KiB total decoded cap, depth $\le 2$) to prevent algorithmic DoS. |
| **Synthetic Trailing Tool-Turn Authority Spoofing** | Client-side request transformers that append a forged `assistant` tool call + `tool` output immediately after a `user` turn (so upstream monitors observe a trailing `tool` role), claiming pre-authorized workspace status and instructing the model to execute the preceding user prompt. | Structural JSON envelope detector inspecting OpenAI `messages`, Responses `input`, and Gemini `contents` against empty/echo arguments, declared `required` parameters, and absent `thoughtSignature`. |

---

## 3. System Design Principles

1. **Inspection-Only Immutability:** Normalization and variant decoding never mutate the upstream request bytes. `HTTPMiddleware` restores original streams byte-for-byte, including reassembling streams exceeding the envelope scan cap.
2. **Metadata-Only Telemetry:** `Result` contains only boolean decisions, integer scores, category identifiers, and rule reason keys—never raw user prompt excerpts—allowing safe security auditing without creating a secondary store of sensitive user content.
3. **Dual Public / Private Rule Architecture:** Publishing the engine, de-obfuscation stack, and research taxonomy openly enables community audit and benchmark reproducibility, while runtime JSON rulepacks (`WithRulepackJSON`) allow production gateways to keep live, rapidly rotating operational signatures confidential.
4. **Algorithmic DoS Resistance:**
   - Single-pass $O(N)$ Aho-Corasick scanning with dynamically sized bitmasks.
   - Fast-path ASCII & Han rune guards avoiding unnecessary NFKC, HTML unescaping, CJK folding, or keyboard-layout decoding on clean English traffic.
   - Five-window UTF-8-safe sampling (`Head / Q1 / Mid / Q3 / Tail`) on oversized prompts while skipping base64 media payloads and encrypted reasoning tokens.

---

## 4. Evaluation Summary

- **Correctness & Race Safety:** Verified via `go test -race -count=1 ./...` covering all obfuscation layers, structural tool-spoofing vectors (Chat Completions + Responses API), HTTP middleware stream preservation, concurrent goroutine stress tests, and zero-false-positive benign corpora across EN/RU/UK/ZH.
- **Latency (Apple M2 Pro, arm64):**
  - 2 KB benign prompt: **0.69 ms** (21 allocs/op)
  - 256 KB multimodal JSON envelope with inline PNG: **1.31 ms** (**187.3 MB/s**)
  - Obfuscated homoglyph / Traditional Wenyan attacks: **33–36 µs**

---

## 5. Limitations and Complementary Layers

Deterministic pre-filtering is **not** a standalone replacement for model-level alignment or semantic neural classifiers. Novel paraphrased zero-shot attacks that use no known structural scaffolding or obfuscation will pass a deterministic pre-filter and must be handled by model alignment and downstream classifiers. Used together, however, deterministic pre-filtering strips high-volume automated kits, smuggling channels, and structural JSON exploits at microsecond cost before invoking heavier safety layers.
