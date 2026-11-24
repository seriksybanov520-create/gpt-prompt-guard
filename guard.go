// Package gptguard provides a sub-millisecond, deterministic prompt-injection
// and multilingual jailbreak prefilter for OpenAI-compatible LLM gateways
// (Chat Completions, Responses API, Realtime API, and Anthropic Messages).
//
// It requires zero GPU or LLM classifier calls and inspects requests without
// mutating forwarded payloads. Production operators can combine the bundled
// public research rulepack with private runtime JSON rulepacks.
package gptguard

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Mode controls blocking strictness for CheckText.
type Mode string

const (
	// ModeLight blocks high-confidence attacks (composite rules, obfuscated
	// attacks, or multi-category combinations) when score >= BlockThreshold.
	ModeLight Mode = "light"
	// ModeStrict blocks any request whose score >= BlockThreshold.
	ModeStrict Mode = "strict"
	// ModeOff disables general CheckText scoring while preserving mandatory
	// instruction-boundary rules when CheckInstructions/CheckBody are called.
	ModeOff Mode = "off"
)

const (
	// DefaultEnvelopeMaxBodyBytes caps pre-concurrency JSON envelope scanning
	// (24 MB) while skipping opaque base64 media and encrypted reasoning blobs.
	DefaultEnvelopeMaxBodyBytes = 24 << 20
	defaultMaxTextBudgetBytes   = 6 << 20
	defaultStringWindowBytes    = 384 << 10
	defaultCombinedWindowBytes  = 896 << 10
)

// Rule defines a single-category weighted pattern group.
type Rule struct {
	Category string   `json:"category"`
	Score    int      `json:"score"`
	Patterns []string `json:"patterns"`
}

// CompositeRule defines a multi-signal rule where every pattern in at least
// one AnyOf clause must match (optionally within MaxWindowRunes of the first
// anchor pattern and without crossing turn/field boundaries).
type CompositeRule struct {
	Category       string     `json:"category"`
	Score          int        `json:"score"`
	MaxWindowRunes int        `json:"max_window_runes,omitempty"`
	Reason         string     `json:"reason"`
	Mandatory      bool       `json:"mandatory,omitempty"`
	AnyOf          [][]string `json:"any_of"`
}

// Rulepack is the JSON schema for loading external or private rule extensions
// at runtime without modifying public source code.
type Rulepack struct {
	Version        string          `json:"version,omitempty"`
	Rules          []Rule          `json:"rules,omitempty"`
	CompositeRules []CompositeRule `json:"composite_rules,omitempty"`
	ExtraPatterns  []string        `json:"extra_block_patterns,omitempty"`
	Allowlist      []string        `json:"allowlist,omitempty"`
}

// Result summarizes a deterministic Prompt Guard inspection decision.
// It is intentionally metadata-only and never echoes raw user prompt text.
type Result struct {
	Blocked     bool     `json:"blocked"`
	Flagged     bool     `json:"flagged"`
	Allowlisted bool     `json:"allowlisted"`
	Score       int      `json:"score"`
	Categories  []string `json:"categories,omitempty"`
	Reasons     []string `json:"reasons,omitempty"`
}

// Config controls Guard behavior. Prefer New(opts...) over constructing Config directly.
type Config struct {
	Mode                 Mode
	FlagThreshold        int
	BlockThreshold       int
	ModelPrefixes        []string
	EnvelopeMaxBodyBytes int
	Rules                []Rule
	CompositeRules       []CompositeRule
	ExtraBlockPatterns   []string
	Allowlist            []string
	DisableDefaultRules  bool
}

// Option customizes a Guard instance.
type Option func(*Config) error

// WithMode sets ModeLight (default), ModeStrict, or ModeOff.
func WithMode(m Mode) Option {
	return func(c *Config) error {
		switch m {
		case ModeLight, ModeStrict, ModeOff:
			c.Mode = m
			return nil
		default:
			return fmt.Errorf("gptguard: unsupported mode %q", m)
		}
	}
}

// WithThresholds configures flag and block score thresholds.
func WithThresholds(flagThreshold, blockThreshold int) Option {
	return func(c *Config) error {
		if flagThreshold < 0 || blockThreshold <= 0 {
			return errors.New("gptguard: thresholds must be non-negative and blockThreshold > 0")
		}
		c.FlagThreshold = flagThreshold
		c.BlockThreshold = blockThreshold
		return nil
	}
}

// WithModelPrefixes restricts scanning to models matching any prefix (case-insensitive,
// matching after optional provider namespaces such as `openai/gpt-6.2-sol`).
// Passing no prefixes (or WithAllModels()) inspects every model.
func WithModelPrefixes(prefixes ...string) Option {
	return func(c *Config) error {
		cleaned := make([]string, 0, len(prefixes))
		for _, p := range prefixes {
			if s := strings.ToLower(strings.TrimSpace(p)); s != "" {
				cleaned = append(cleaned, s)
			}
		}
		c.ModelPrefixes = cleaned
		return nil
	}
}

// WithAllModels disables model-prefix filtering so every model name is inspected.
func WithAllModels() Option {
	return func(c *Config) error {
		c.ModelPrefixes = nil
		return nil
	}
}

// WithEnvelopeMaxBodyBytes overrides the maximum JSON body size inspected by CheckBody.
func WithEnvelopeMaxBodyBytes(n int) Option {
	return func(c *Config) error {
		if n <= 0 {
			return errors.New("gptguard: EnvelopeMaxBodyBytes must be > 0")
		}
		c.EnvelopeMaxBodyBytes = n
		return nil
	}
}

// WithDisableDefaultRules starts from an empty ruleset (useful when supplying a
// fully custom rulepack).
func WithDisableDefaultRules() Option {
	return func(c *Config) error {
		c.DisableDefaultRules = true
		return nil
	}
}

// WithExtraRules appends additional single-category weighted rules.
func WithExtraRules(rules ...Rule) Option {
	return func(c *Config) error {
		c.Rules = append(c.Rules, rules...)
		return nil
	}
}

// WithExtraCompositeRules appends additional multi-signal composite rules.
func WithExtraCompositeRules(rules ...CompositeRule) Option {
	return func(c *Config) error {
		c.CompositeRules = append(c.CompositeRules, rules...)
		return nil
	}
}

// WithExtraBlockPatterns adds immediate operator blocklist substrings.
func WithExtraBlockPatterns(patterns ...string) Option {
	return func(c *Config) error {
		for _, p := range patterns {
			if norm := NormalizeText(p); norm != "" {
				c.ExtraBlockPatterns = append(c.ExtraBlockPatterns, norm)
			}
		}
		return nil
	}
}

// WithAllowlist registers patterns that mark low-confidence flags as allowlisted.
// Allowlist patterns never bypass high-confidence attacks or mandatory rules.
func WithAllowlist(patterns ...string) Option {
	return func(c *Config) error {
		for _, p := range patterns {
			if norm := NormalizeText(p); norm != "" {
				c.Allowlist = append(c.Allowlist, norm)
			}
		}
		return nil
	}
}

// WithRulepackJSON loads additional rules, composite rules, extra block patterns,
// and allowlist entries from JSON (for example a private operational rulepack).
func WithRulepackJSON(data []byte) Option {
	return func(c *Config) error {
		var rp Rulepack
		if err := json.Unmarshal(data, &rp); err != nil {
			return fmt.Errorf("gptguard: parse rulepack json: %w", err)
		}
		c.Rules = append(c.Rules, rp.Rules...)
		c.CompositeRules = append(c.CompositeRules, rp.CompositeRules...)
		for _, p := range rp.ExtraPatterns {
			if norm := NormalizeText(p); norm != "" {
				c.ExtraBlockPatterns = append(c.ExtraBlockPatterns, norm)
			}
		}
		for _, p := range rp.Allowlist {
			if norm := NormalizeText(p); norm != "" {
				c.Allowlist = append(c.Allowlist, norm)
			}
		}
		return nil
	}
}

// Guard is an immutable, concurrency-safe prompt-injection & jailbreak prefilter.
type Guard struct {
	mode                 Mode
	flagThreshold        int
	blockThreshold       int
	modelPrefixes        []string
	envelopeMaxBodyBytes int
	rules                []Rule
	compositeRules       []CompositeRule
	mandatoryRules       []CompositeRule
	highConfidenceCats   map[string]struct{}
	extraBlockPatterns   []string
	allowlist            []string
	ac                   *automaton
}

// New compiles a concurrency-safe Guard from the bundled public research rulepack
// plus any caller-supplied options or external rulepacks.
func New(opts ...Option) (*Guard, error) {
	cfg := Config{
		Mode:                 ModeLight,
		FlagThreshold:        5,
		BlockThreshold:       7,
		ModelPrefixes:        []string{"gpt", "o1", "o3", "o4", "codex", "claude"},
		EnvelopeMaxBodyBytes: DefaultEnvelopeMaxBodyBytes,
	}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(&cfg); err != nil {
			return nil, err
		}
	}

	var allRules []Rule
	var allComposites []CompositeRule
	if !cfg.DisableDefaultRules {
		allRules = append(allRules, DefaultPublicRules()...)
		allComposites = append(allComposites, DefaultPublicCompositeRules()...)
	}
	allRules = append(allRules, cfg.Rules...)
	allComposites = append(allComposites, cfg.CompositeRules...)

	// Normalize all configured patterns once at construction time so callers can
	// write natural casing in custom JSON rulepacks.
	normRules := make([]Rule, 0, len(allRules))
	for _, r := range allRules {
		if strings.TrimSpace(r.Category) == "" || len(r.Patterns) == 0 {
			continue
		}
		pats := make([]string, 0, len(r.Patterns))
		for _, p := range r.Patterns {
			if np := NormalizeText(p); np != "" {
				pats = append(pats, np)
			}
		}
		if len(pats) > 0 {
			normRules = append(normRules, Rule{
				Category: strings.TrimSpace(r.Category),
				Score:    r.Score,
				Patterns: pats,
			})
		}
	}

	normComposites := make([]CompositeRule, 0, len(allComposites))
	var mandatory []CompositeRule
	highConf := map[string]struct{}{
		"custom_blocklist": {},
	}
	for _, cr := range allComposites {
		cat := strings.TrimSpace(cr.Category)
		if cat == "" || len(cr.AnyOf) == 0 {
			continue
		}
		anyOf := make([][]string, 0, len(cr.AnyOf))
		for _, clause := range cr.AnyOf {
			var normClause []string
			for _, p := range clause {
				if np := NormalizeText(p); np != "" {
					normClause = append(normClause, np)
				}
			}
			if len(normClause) > 0 {
				anyOf = append(anyOf, normClause)
			}
		}
		if len(anyOf) == 0 {
			continue
		}
		reason := strings.TrimSpace(cr.Reason)
		if reason == "" {
			reason = cat
		}
		score := cr.Score
		if score <= 0 {
			score = 15
		}
		compiled := CompositeRule{
			Category:       cat,
			Score:          score,
			MaxWindowRunes: cr.MaxWindowRunes,
			Reason:         reason,
			Mandatory:      cr.Mandatory,
			AnyOf:          anyOf,
		}
		normComposites = append(normComposites, compiled)
		highConf[cat] = struct{}{}
		if compiled.Mandatory {
			mandatory = append(mandatory, compiled)
		}
	}

	ac := buildAutomaton(normRules, normComposites, mandatory)

	return &Guard{
		mode:                 cfg.Mode,
		flagThreshold:        cfg.FlagThreshold,
		blockThreshold:       cfg.BlockThreshold,
		modelPrefixes:        cfg.ModelPrefixes,
		envelopeMaxBodyBytes: cfg.EnvelopeMaxBodyBytes,
		rules:                normRules,
		compositeRules:       normComposites,
		mandatoryRules:       mandatory,
		highConfidenceCats:   highConf,
		extraBlockPatterns:   cfg.ExtraBlockPatterns,
		allowlist:            cfg.Allowlist,
		ac:                   ac,
	}, nil
}

// AutomatonPatternCount reports the number of unique anchor strings compiled into
// the guard's Aho-Corasick automaton.
func (g *Guard) AutomatonPatternCount() int {
	return g.ac.patternCount()
}

// ModelInScope reports whether modelName matches the configured prefix scope.
func (g *Guard) ModelInScope(modelName string) bool {
	if len(g.modelPrefixes) == 0 {
		return true
	}
	lower := strings.ToLower(strings.TrimSpace(modelName))
	if lower == "" {
		return false
	}
	// Strip provider path prefixes (`openai/gpt-6.2-sol`, `azure/gpt-5`) and
	// dotted region prefixes (`us.anthropic.claude-opus-4`).
	candidates := []string{lower}
	if idx := strings.LastIndexByte(lower, '/'); idx >= 0 && idx+1 < len(lower) {
		candidates = append(candidates, lower[idx+1:])
	}
	for _, cand := range candidates {
		for _, prefix := range g.modelPrefixes {
			if strings.HasPrefix(cand, prefix) || strings.Contains(cand, "."+prefix) {
				return true
			}
		}
	}
	return false
}

// CheckText runs full multi-layer inspection on plain text for an in-scope model.
func (g *Guard) CheckText(modelName, text string) Result {
	if g.mode == ModeOff || !g.ModelInScope(modelName) || strings.TrimSpace(text) == "" {
		return Result{}
	}
	if len(text) > defaultCombinedWindowBytes {
		text = sampleLargeText(text, defaultCombinedWindowBytes)
	}
	return g.checkTextWithVariants(text, g.generateVariants(text))
}

func (g *Guard) checkTextWithVariants(text string, variants []textVariant) Result {
	if g.mode == ModeOff || len(variants) == 0 {
		return Result{}
	}
	normalized := variants[0].Text
	literalNormalized := literalText(text)

	allowlisted := false
	for _, pat := range g.allowlist {
		if pat != "" && strings.Contains(normalized, pat) {
			allowlisted = true
			break
		}
	}

	score := 0
	categorySet := map[string]struct{}{}
	reasonSet := map[string]struct{}{}
	matchedObfuscationVariant := false

	ruleScore, ruleObf := g.scoreRuleVariants(variants, literalNormalized, categorySet, reasonSet)
	score += ruleScore
	matchedObfuscationVariant = matchedObfuscationVariant || ruleObf

	obfCategories := map[string]struct{}{}
	obfReasons := map[string]struct{}{}
	obfScore := scoreObfuscationSignals(text, normalized, obfCategories, obfReasons)
	if obfScore > 2 {
		obfScore = 2
	}

	compositeScore, compObf := g.scoreCompositeVariants(variants, literalNormalized, g.compositeRules, categorySet, reasonSet)
	score += compositeScore
	matchedObfuscationVariant = matchedObfuscationVariant || compObf

	if HasZeroWidthStegEnvelope(text) {
		score += 15
		categorySet["zero_width_steganography"] = struct{}{}
		categorySet["unicode_smuggling"] = struct{}{}
		categorySet["prompt_obfuscation"] = struct{}{}
		reasonSet["zero_width_steg_envelope"] = struct{}{}
		matchedObfuscationVariant = true
	}
	if matchedObfuscationVariant {
		score += 3
		categorySet["obfuscation_evasion"] = struct{}{}
		reasonSet["derived_obfuscation_variant"] = struct{}{}
	}
	if obfScore > 0 && (matchedObfuscationVariant || (ruleScore == 0 && compositeScore == 0)) {
		score += obfScore
		for k := range obfCategories {
			categorySet[k] = struct{}{}
		}
		for k := range obfReasons {
			reasonSet[k] = struct{}{}
		}
	}

	customMatched := false
	for _, pat := range g.extraBlockPatterns {
		if pat == "" {
			continue
		}
		if matched, source := containsVariantPattern(variants, pat); matched {
			if strings.Contains(literalNormalized, pat) {
				source = ""
			}
			score += g.blockThreshold
			categorySet["custom_blocklist"] = struct{}{}
			reasonSet["custom_pattern"] = struct{}{}
			recordVariantSource(source, categorySet, reasonSet)
			customMatched = true
			break
		}
	}

	blocked := g.shouldBlock(score, categorySet, reasonSet)
	hasRuleSignal := ruleScore > 0 || compositeScore > 0 || matchedObfuscationVariant || customMatched
	flagged := !blocked && hasRuleSignal && g.flagThreshold > 0 && score >= g.flagThreshold

	return Result{
		Blocked:     blocked,
		Flagged:     flagged,
		Allowlisted: allowlisted && !blocked,
		Score:       score,
		Categories:  sortedKeys(categorySet),
		Reasons:     sortedKeys(reasonSet),
	}
}

// CheckInstructions enforces mandatory high-confidence boundary rules
// unconditionally (even in ModeOff) before running general CheckText scoring.
func (g *Guard) CheckInstructions(modelName, text string) Result {
	if strings.TrimSpace(text) == "" || !g.ModelInScope(modelName) {
		return Result{}
	}
	if len(text) > defaultCombinedWindowBytes {
		text = sampleLargeText(text, defaultCombinedWindowBytes)
	}
	variants := g.generateVariants(text)
	if res := g.checkMandatoryWithVariants(text, variants); res.Blocked {
		return res
	}
	return g.checkTextWithVariants(text, variants)
}

// CheckBody inspects a complete OpenAI/Anthropic/Gemini JSON request envelope
// without mutating body. It detects structural trailing tool-authority spoofs,
// skips opaque base64 media & encrypted reasoning blobs, and returns (result, scanned).
func (g *Guard) CheckBody(modelName string, body []byte) (Result, bool) {
	if len(body) == 0 || len(body) > g.envelopeMaxBodyBytes || !isValidJSONEnvelope(body) {
		return Result{}, false
	}
	if !g.ModelInScope(modelName) {
		return Result{}, true
	}
	if reason, ok := DetectSyntheticTrailingToolAuthoritySpoof(body); ok {
		return Result{
			Blocked:    true,
			Score:      15,
			Categories: []string{"synthetic_tool_authority_spoof"},
			Reasons:    []string{reason},
		}, true
	}
	var values []string
	budget := defaultMaxTextBudgetBytes
	collectJSONStrings(body, defaultStringWindowBytes, &values, &budget)
	if len(values) == 0 {
		return Result{}, true
	}
	return g.CheckInstructions(modelName, strings.Join(values, "\n")), true
}

func (g *Guard) checkMandatoryWithVariants(text string, variants []textVariant) Result {
	if len(variants) == 0 {
		return Result{}
	}
	categorySet := map[string]struct{}{}
	reasonSet := map[string]struct{}{}
	literalNormalized := literalText(text)

	score, _ := g.scoreCompositeVariants(variants, literalNormalized, g.mandatoryRules, categorySet, reasonSet)
	if HasZeroWidthStegEnvelope(text) {
		score += 15
		categorySet["zero_width_steganography"] = struct{}{}
		categorySet["unicode_smuggling"] = struct{}{}
		categorySet["prompt_obfuscation"] = struct{}{}
		reasonSet["zero_width_steg_envelope"] = struct{}{}
	}

	ruleCats := map[string]struct{}{}
	ruleReasons := map[string]struct{}{}
	genericScore, _ := g.scoreRuleVariants(variants, literalNormalized, ruleCats, ruleReasons)
	if hasUnrestrictedRefusalFixtureScaffold(ruleCats) {
		for k := range ruleCats {
			categorySet[k] = struct{}{}
		}
		for k := range ruleReasons {
			reasonSet[k] = struct{}{}
		}
		score += genericScore
		if score < 15 {
			score = 15
		}
		categorySet["unrestricted_prompt_bundle"] = struct{}{}
		reasonSet["unrestricted_refusal_fixture_scaffold"] = struct{}{}
	}
	if score == 0 {
		return Result{}
	}
	return Result{
		Blocked:    true,
		Score:      score,
		Categories: sortedKeys(categorySet),
		Reasons:    sortedKeys(reasonSet),
	}
}

func (g *Guard) containsKnownSignal(normalized string) bool {
	if normalized == "" {
		return false
	}
	present := make([]uint64, g.ac.words)
	if !g.ac.scan(normalized, present) {
		return false
	}
	for _, r := range g.rules {
		for _, p := range r.Patterns {
			if g.ac.mayContain(present, p) && strings.Contains(normalized, p) {
				return true
			}
		}
	}
	for _, cr := range g.compositeRules {
		for _, allOf := range cr.AnyOf {
			if len(allOf) > 0 && g.ac.mayContain(present, allOf[0]) && containsAllSignals(normalized, allOf) {
				return true
			}
		}
	}
	return false
}

func (g *Guard) scoreRuleVariants(variants []textVariant, literalNormalized string, categorySet, reasonSet map[string]struct{}) (int, bool) {
	score := 0
	matchedObf := false
	matchedRules := map[string]struct{}{}
	present := make([]uint64, g.ac.words)

	for _, candidate := range variants {
		if !g.ac.scan(candidate.Text, present) {
			continue
		}
		for _, rule := range g.rules {
			if _, ok := matchedRules[rule.Category]; ok {
				continue
			}
			for _, pattern := range rule.Patterns {
				if !g.ac.mayContain(present, pattern) || !containsWordBounded(candidate.Text, pattern) {
					continue
				}
				score += rule.Score
				categorySet[rule.Category] = struct{}{}
				reasonSet[pattern] = struct{}{}
				source := candidate.Source
				if containsWordBounded(literalNormalized, pattern) {
					source = ""
				}
				matchedObf = recordVariantSource(source, categorySet, reasonSet) || matchedObf
				matchedRules[rule.Category] = struct{}{}
				break
			}
		}
	}

	if _, ok := matchedRules["roleplay_jailbreak"]; !ok &&
		(hasKey(categorySet, "system_override") || hasKey(categorySet, "prompt_leak")) {
		for _, candidate := range variants {
			matched := false
			for _, pattern := range contextualDeveloperModePatterns {
				if !containsWordBounded(candidate.Text, pattern) {
					continue
				}
				score += 4
				categorySet["roleplay_jailbreak"] = struct{}{}
				reasonSet[pattern] = struct{}{}
				source := candidate.Source
				if containsWordBounded(literalNormalized, pattern) {
					source = ""
				}
				matchedObf = recordVariantSource(source, categorySet, reasonSet) || matchedObf
				matched = true
				break
			}
			if matched {
				break
			}
		}
	}
	return score, matchedObf
}

func (g *Guard) scoreCompositeVariants(variants []textVariant, literalNormalized string, rules []CompositeRule, categorySet, reasonSet map[string]struct{}) (int, bool) {
	if len(rules) == 0 || len(variants) == 0 {
		return 0, false
	}
	words := g.ac.words
	masks := make([]uint64, len(variants)*words)
	hits := make([]bool, len(variants))
	anyHit := false
	for i := range variants {
		slice := masks[i*words : (i+1)*words]
		hits[i] = g.ac.scan(variants[i].Text, slice)
		if hits[i] {
			anyHit = true
		}
	}
	if !anyHit {
		return 0, false
	}

	score := 0
	matchedObf := false
	for _, rule := range rules {
		matched := false
		for vIdx, variant := range variants {
			if !hits[vIdx] {
				continue
			}
			present := masks[vIdx*words : (vIdx+1)*words]
			for _, allOf := range rule.AnyOf {
				if len(allOf) > 0 && !g.ac.mayContain(present, allOf[0]) {
					continue
				}
				if !matchesCompositeSignals(variant.Text, allOf, rule.MaxWindowRunes) {
					continue
				}
				score += rule.Score
				categorySet[rule.Category] = struct{}{}
				reasonSet[rule.Reason] = struct{}{}
				source := variant.Source
				if matchesCompositeSignals(literalNormalized, allOf, rule.MaxWindowRunes) {
					source = ""
				}
				matchedObf = recordVariantSource(source, categorySet, reasonSet) || matchedObf
				matched = true
				break
			}
			if matched {
				break
			}
		}
	}
	return score, matchedObf
}

func containsVariantPattern(variants []textVariant, pattern string) (bool, string) {
	for _, candidate := range variants {
		if strings.Contains(candidate.Text, pattern) {
			return true, candidate.Source
		}
	}
	return false, ""
}

func (g *Guard) shouldBlock(score int, categorySet, reasonSet map[string]struct{}) bool {
	if score <= 0 || g.mode == ModeOff {
		return false
	}
	if g.mode == ModeStrict {
		return score >= g.blockThreshold
	}
	return score >= g.blockThreshold && g.isHighConfidenceAttack(categorySet, reasonSet)
}

func hasUnrestrictedRefusalFixtureScaffold(categorySet map[string]struct{}) bool {
	return hasKey(categorySet, "refusal_fallback_suppression") &&
		hasKey(categorySet, "synthetic_fixture_relabeling") &&
		(hasKey(categorySet, "forced_response_template") || hasKey(categorySet, "roleplay_jailbreak"))
}

func (g *Guard) isHighConfidenceAttack(categorySet, reasonSet map[string]struct{}) bool {
	for cat := range categorySet {
		if _, ok := g.highConfidenceCats[cat]; ok {
			return true
		}
	}
	if hasKey(categorySet, "zero_width_steganography") || hasKey(categorySet, "synthetic_tool_authority_spoof") {
		return true
	}
	if hasUnrestrictedRefusalFixtureScaffold(categorySet) {
		return true
	}
	if hasKey(categorySet, "persona_hijack") && hasKey(categorySet, "refusal_suppression") {
		return true
	}
	if hasKey(categorySet, "fake_authority") && hasKey(categorySet, "refusal_suppression") {
		return true
	}
	if hasKey(categorySet, "prompt_leak") &&
		(hasKey(categorySet, "system_override") || hasKey(categorySet, "roleplay_jailbreak")) {
		return true
	}
	if hasKey(categorySet, "system_override") && hasKey(categorySet, "roleplay_jailbreak") {
		return true
	}
	if hasKey(categorySet, "obfuscation_instruction") && hasKey(categorySet, "system_override") {
		return true
	}
	if hasKey(categorySet, "prompt_obfuscation") &&
		(hasKey(categorySet, "prompt_leak") ||
			hasKey(categorySet, "system_override") ||
			hasKey(categorySet, "roleplay_jailbreak") ||
			hasKey(categorySet, "indirect_injection") ||
			hasKey(categorySet, "fake_authority") ||
			hasKey(categorySet, "persona_hijack") ||
			hasKey(categorySet, "refusal_suppression")) {
		return true
	}
	if hasKey(categorySet, "keyboard_layout_obfuscation") &&
		(hasKey(categorySet, "prompt_leak") ||
			hasKey(categorySet, "system_override") ||
			hasKey(categorySet, "roleplay_jailbreak") ||
			hasKey(categorySet, "indirect_injection") ||
			hasKey(categorySet, "obfuscation_instruction")) {
		return true
	}
	return hasKey(reasonSet, "custom_pattern")
}

func hasKey(set map[string]struct{}, key string) bool {
	_, ok := set[key]
	return ok
}

func sortedKeys(set map[string]struct{}) []string {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
