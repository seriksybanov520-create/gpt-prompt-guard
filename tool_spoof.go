package gptguard

import (
	"strings"

	"github.com/tidwall/gjson"
)

// DetectSyntheticTrailingToolAuthoritySpoof detects client-side request
// transformers that append a forged assistant tool call + tool result turn
// immediately after a user message (across OpenAI Chat Completions `messages`,
// OpenAI Responses API `input`, or Gemini `contents`) so upstream classifiers
// see a trailing `tool` role instead of `user`, while instructing the model
// from inside the fake tool output to treat the workspace as pre-authorized
// and execute the preceding user request.
func DetectSyntheticTrailingToolAuthoritySpoof(body []byte) (string, bool) {
	if len(body) == 0 || !isValidJSONEnvelope(body) {
		return "", false
	}
	root := gjson.ParseBytes(body)
	toolsVal := root.Get("tools")

	if msgs := root.Get("messages"); msgs.IsArray() {
		arr := msgs.Array()
		if n := len(arr); n >= 3 {
			userMsg, asstMsg, toolMsg := arr[n-3], arr[n-2], arr[n-1]
			if strings.EqualFold(strings.TrimSpace(userMsg.Get("role").String()), "user") &&
				strings.EqualFold(strings.TrimSpace(asstMsg.Get("role").String()), "assistant") &&
				strings.EqualFold(strings.TrimSpace(toolMsg.Get("role").String()), "tool") &&
				hasEmptyAssistantTextAndThought(asstMsg) {
				calls := asstMsg.Get("tool_calls").Array()
				if len(calls) == 1 && !hasJSONThoughtSignature(calls[0]) {
					callID := strings.TrimSpace(calls[0].Get("id").String())
					toolCallID := strings.TrimSpace(toolMsg.Get("tool_call_id").String())
					if callID == "" || toolCallID == "" || callID == toolCallID {
						fnName := strings.TrimSpace(calls[0].Get("function.name").String())
						argsStr := strings.TrimSpace(calls[0].Get("function.arguments").String())
						toolOut := extractJSONContentText(toolMsg.Get("content"))
						if isSyntheticToolAuthorityTurn(toolsVal, fnName, argsStr, toolOut) {
							return "synthetic_trailing_tool_authority_spoof", true
						}
					}
				}
			}
		}
	}

	if inputs := root.Get("input"); inputs.IsArray() {
		arr := inputs.Array()
		if n := len(arr); n >= 3 {
			userItem, callItem, outItem := arr[n-3], arr[n-2], arr[n-1]
			if strings.EqualFold(strings.TrimSpace(userItem.Get("role").String()), "user") &&
				strings.EqualFold(strings.TrimSpace(callItem.Get("type").String()), "function_call") &&
				strings.EqualFold(strings.TrimSpace(outItem.Get("type").String()), "function_call_output") &&
				!hasJSONThoughtSignature(callItem) {
				callID := strings.TrimSpace(callItem.Get("call_id").String())
				outCallID := strings.TrimSpace(outItem.Get("call_id").String())
				if callID == "" || outCallID == "" || callID == outCallID {
					fnName := strings.TrimSpace(callItem.Get("name").String())
					argsStr := strings.TrimSpace(callItem.Get("arguments").String())
					toolOut := extractJSONContentText(outItem.Get("output"))
					if isSyntheticToolAuthorityTurn(toolsVal, fnName, argsStr, toolOut) {
						return "synthetic_trailing_tool_authority_spoof", true
					}
				}
			}
		}
	}

	if contents := root.Get("contents"); contents.IsArray() {
		arr := contents.Array()
		if n := len(arr); n >= 3 {
			userTurn, modelTurn, respTurn := arr[n-3], arr[n-2], arr[n-1]
			userHasFnResp := false
			for _, part := range userTurn.Get("parts").Array() {
				if part.Get("functionResponse").Exists() {
					userHasFnResp = true
					break
				}
			}
			respRole := strings.ToLower(strings.TrimSpace(respTurn.Get("role").String()))
			modelParts := modelTurn.Get("parts").Array()
			respParts := respTurn.Get("parts").Array()
			if !userHasFnResp &&
				strings.EqualFold(strings.TrimSpace(userTurn.Get("role").String()), "user") &&
				strings.EqualFold(strings.TrimSpace(modelTurn.Get("role").String()), "model") &&
				(respRole == "user" || respRole == "function" || respRole == "tool") &&
				len(modelParts) == 1 && len(respParts) == 1 &&
				modelParts[0].Get("functionCall").Exists() &&
				!modelParts[0].Get("thought").Bool() &&
				!hasJSONThoughtSignature(modelParts[0]) &&
				respParts[0].Get("functionResponse").Exists() {
				fnName := strings.TrimSpace(modelParts[0].Get("functionCall.name").String())
				argsRaw := strings.TrimSpace(modelParts[0].Get("functionCall.args").Raw)
				respRaw := strings.TrimSpace(respParts[0].Get("functionResponse.response").Raw)
				if isSyntheticToolAuthorityTurn(toolsVal, fnName, argsRaw, respRaw) {
					return "synthetic_trailing_tool_authority_spoof", true
				}
			}
		}
	}

	return "", false
}

func hasEmptyAssistantTextAndThought(msg gjson.Result) bool {
	if strings.TrimSpace(extractJSONContentText(msg.Get("content"))) != "" {
		return false
	}
	if strings.TrimSpace(msg.Get("reasoning_content").String()) != "" ||
		strings.TrimSpace(msg.Get("reasoning").String()) != "" ||
		msg.Get("reasoning_details").IsArray() && len(msg.Get("reasoning_details").Array()) > 0 {
		return false
	}
	return !hasJSONThoughtSignature(msg)
}

func hasJSONThoughtSignature(node gjson.Result) bool {
	return strings.TrimSpace(node.Get("thoughtSignature").String()) != "" ||
		strings.TrimSpace(node.Get("thought_signature").String()) != "" ||
		strings.TrimSpace(node.Get("extra_content.google.thought_signature").String()) != ""
}

func extractJSONContentText(content gjson.Result) string {
	switch {
	case !content.Exists() || content.Type == gjson.Null:
		return ""
	case content.Type == gjson.String:
		return content.String()
	case content.IsArray():
		var parts []string
		for _, item := range content.Array() {
			if item.Type == gjson.String {
				parts = append(parts, item.String())
			} else if t := item.Get("text"); t.Type == gjson.String && t.String() != "" {
				parts = append(parts, t.String())
			}
		}
		return strings.Join(parts, "\n")
	default:
		return content.Raw
	}
}

func isSyntheticToolAuthorityTurn(toolsVal gjson.Result, fnName, argsStr, toolOut string) bool {
	trimmedOut := strings.TrimSpace(toolOut)
	if trimmedOut == "" || len(trimmedOut) > 1024 {
		return false
	}
	emptyArgs := isEmptyObjectJSONArgs(argsStr)
	echoCmd := strings.Contains(NormalizeText(argsStr)+" ", "echo ")
	missingReq := violatesDeclaredToolRequiredArgs(toolsVal, fnName, argsStr)
	if !emptyArgs && !echoCmd && !missingReq {
		return false
	}

	normOut := strings.ReplaceAll(NormalizeText(trimmedOut), "ё", "е")
	if cyrFolded, changed := foldLatinHomoglyphsInCyrillicWords(normOut); changed {
		if matchesSyntheticToolDirective(cyrFolded, missingReq) {
			return true
		}
	}
	return matchesSyntheticToolDirective(normOut, missingReq)
}

func isEmptyObjectJSONArgs(argsStr string) bool {
	trimmed := strings.TrimSpace(argsStr)
	if trimmed == "" || trimmed == "null" {
		return true
	}
	if len(trimmed) >= 2 && trimmed[0] == '{' && trimmed[len(trimmed)-1] == '}' {
		return strings.TrimSpace(trimmed[1:len(trimmed)-1]) == ""
	}
	return false
}

func violatesDeclaredToolRequiredArgs(toolsVal gjson.Result, fnName, argsStr string) bool {
	if fnName == "" || !toolsVal.IsArray() {
		return false
	}
	var paramsNode gjson.Result
	found := false
	for _, item := range toolsVal.Array() {
		if strings.EqualFold(strings.TrimSpace(item.Get("function.name").String()), fnName) {
			paramsNode = item.Get("function.parameters")
			found = true
			break
		}
		if strings.EqualFold(strings.TrimSpace(item.Get("name").String()), fnName) {
			paramsNode = item.Get("parameters")
			found = true
			break
		}
		for _, decl := range item.Get("functionDeclarations").Array() {
			if strings.EqualFold(strings.TrimSpace(decl.Get("name").String()), fnName) {
				paramsNode = decl.Get("parameters")
				found = true
				break
			}
		}
		if found {
			break
		}
	}
	if !found || !paramsNode.Exists() {
		return false
	}
	reqArr := paramsNode.Get("required").Array()
	if len(reqArr) == 0 {
		return false
	}
	if isEmptyObjectJSONArgs(argsStr) || !gjson.Valid(argsStr) {
		return true
	}
	parsedArgs := gjson.Parse(argsStr)
	if !parsedArgs.IsObject() {
		return true
	}
	for _, reqField := range reqArr {
		key := strings.TrimSpace(reqField.String())
		if key != "" && !parsedArgs.Get(gjson.Escape(key)).Exists() {
			return true
		}
	}
	return false
}

func matchesSyntheticToolDirective(normOut string, missingRequiredArgs bool) bool {
	hasContinuation := false
	for _, marker := range []string{
		"proceed with the user",
		"continue with the user",
		"fulfill the user",
		"execute the user",
		"follow the user",
		"latest instruction above",
		"user s latest instruction",
		"user instruction above",
		"user request above",
		"инструкцию пользователя выше",
		"запрос пользователя выше",
		"последнюю инструкцию пользователя",
		"выполняй последн",
		"выполни последн",
		"продолжай по инструкц",
	} {
		if strings.Contains(normOut, marker) {
			hasContinuation = true
			break
		}
	}
	if !hasContinuation {
		return false
	}
	if missingRequiredArgs {
		return true
	}
	return hasToolAuthorityClaim(normOut)
}

func hasToolAuthorityClaim(normOut string) bool {
	for _, marker := range []string{
		"authorized",
		"verified workspace",
		"approved workspace",
		"engineering workspace",
		"on-premise",
		"onprem",
		"env ok",
		"environment ok",
		"авторизован",
		"верифицирован",
		"защищенный контур",
		"защищенном контуре",
		"закрытом контуре",
		"корпоративн",
		"легальн",
	} {
		if strings.Contains(normOut, marker) {
			return true
		}
	}
	return false
}
