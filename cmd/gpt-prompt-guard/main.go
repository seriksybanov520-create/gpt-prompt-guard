package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	gptguard "github.com/seriksybanov520-create/gpt-prompt-guard"
)

func main() {
	model := flag.String("model", "gpt-5.4", "Target model identifier")
	mode := flag.String("mode", "light", "Guard mode: light | strict | off")
	jsonEnvelope := flag.Bool("json", false, "Treat input as an OpenAI/Anthropic/Gemini JSON request envelope")
	rulepackPath := flag.String("rulepack", "", "Optional path to a custom/private JSON rulepack")
	inputFile := flag.String("file", "", "Optional input file (defaults to stdin)")
	flag.Parse()

	opts := []gptguard.Option{
		gptguard.WithMode(gptguard.Mode(*mode)),
	}
	if *rulepackPath != "" {
		raw, err := os.ReadFile(*rulepackPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read rulepack: %v\n", err)
			os.Exit(2)
		}
		opts = append(opts, gptguard.WithRulepackJSON(raw))
	}

	guard, err := gptguard.New(opts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init guard: %v\n", err)
		os.Exit(2)
	}

	var input []byte
	if *inputFile != "" {
		input, err = os.ReadFile(*inputFile)
	} else {
		input, err = io.ReadAll(os.Stdin)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "read input: %v\n", err)
		os.Exit(2)
	}

	start := time.Now()
	var res gptguard.Result
	if *jsonEnvelope {
		res, _ = guard.CheckBody(*model, input)
	} else {
		res = guard.CheckInstructions(*model, string(input))
	}
	elapsed := time.Since(start)

	out := map[string]any{
		"model":          *model,
		"blocked":        res.Blocked,
		"flagged":        res.Flagged,
		"allowlisted":    res.Allowlisted,
		"score":          res.Score,
		"categories":     res.Categories,
		"reasons":        res.Reasons,
		"latency_micros": elapsed.Microseconds(),
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
	if res.Blocked {
		os.Exit(1)
	}
}
