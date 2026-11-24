package gptguard

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/tidwall/gjson"
)

// MiddlewareConfig customizes HTTPMiddleware behavior.
type MiddlewareConfig struct {
	// StatusCode returned when a request is blocked (defaults to 400 Bad Request).
	StatusCode int
	// ModelExtractor extracts the model name from the request or JSON body.
	// When nil, the middleware reads the top-level JSON `"model"` field.
	ModelExtractor func(r *http.Request, body []byte) string
	// OnDecision is invoked for every scanned request (useful for structured
	// audit telemetry without logging raw user prompt text).
	OnDecision func(r *http.Request, model string, res Result)
}

// HTTPMiddleware wraps an OpenAI-compatible HTTP handler to inspect JSON POST
// bodies before forwarding upstream. Request bodies are restored transparently
// so downstream handlers read the exact original bytes unmodified.
func (g *Guard) HTTPMiddleware(cfg MiddlewareConfig, next http.Handler) http.Handler {
	statusCode := cfg.StatusCode
	if statusCode <= 0 {
		statusCode = http.StatusBadRequest
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body == nil || (r.Method != http.MethodPost && r.Method != http.MethodPut) {
			next.ServeHTTP(w, r)
			return
		}
		if ct := strings.ToLower(r.Header.Get("Content-Type")); ct != "" && !strings.Contains(ct, "json") {
			next.ServeHTTP(w, r)
			return
		}

		maxRead := int64(g.envelopeMaxBodyBytes) + 1
		origBody := r.Body
		body, err := io.ReadAll(io.LimitReader(origBody, maxRead))
		if err != nil {
			r.Body = struct {
				io.Reader
				io.Closer
			}{
				Reader: io.MultiReader(bytes.NewReader(body), origBody),
				Closer: origBody,
			}
			next.ServeHTTP(w, r)
			return
		}
		// If payload exceeds the pre-scan cap, reassemble the full stream
		// byte-for-byte without truncating downstream handlers.
		if int64(len(body)) >= maxRead {
			r.Body = struct {
				io.Reader
				io.Closer
			}{
				Reader: io.MultiReader(bytes.NewReader(body), origBody),
				Closer: origBody,
			}
			next.ServeHTTP(w, r)
			return
		}
		_ = origBody.Close()
		r.Body = io.NopCloser(bytes.NewReader(body))

		model := ""
		if cfg.ModelExtractor != nil {
			model = cfg.ModelExtractor(r, body)
		} else if gjson.ValidBytes(body) {
			model = strings.TrimSpace(gjson.GetBytes(body, "model").String())
		}

		res, scanned := g.CheckBody(model, body)
		if scanned && cfg.OnDecision != nil {
			cfg.OnDecision(r, model, res)
		}
		if res.Blocked {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(statusCode)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]any{
					"message":    "Request blocked by prompt security policy.",
					"type":       "invalid_request_error",
					"code":       "prompt_guard_blocked",
					"categories": res.Categories,
				},
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}
