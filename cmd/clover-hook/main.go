package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const logFile = "/tmp/clover-hook.log"

func logMsg(msg string) {
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "[%s] %s\n", time.Now().Format("15:04:05"), msg)
}

// --- Auth: token exchange + caching ---

type tokenResponse struct {
	AccessToken string `json:"accessToken"`
	ExpiresIn   int    `json:"expiresIn"`
	TokenType   string `json:"tokenType"`
}

type cachedTokenFile struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
}

func getAuthURL() string {
	authURL := getEnv("CLOVER_AUTH_URL", "CLAUDE_PLUGIN_OPTION_AUTH_URL")
	if authURL == "" {
		return "https://clover.frontegg.com"
	}
	return strings.TrimRight(authURL, "/")
}

func tokenCachePath() string {
	dataDir := getEnv("CLAUDE_PLUGIN_DATA")
	if dataDir == "" {
		return "/tmp/clover-token.json"
	}
	return filepath.Join(dataDir, "token.json")
}

func loadCachedToken() (string, bool) {
	data, err := os.ReadFile(tokenCachePath())
	if err != nil {
		return "", false
	}
	var cached cachedTokenFile
	if json.Unmarshal(data, &cached) != nil {
		return "", false
	}
	if time.Now().Unix() >= cached.ExpiresAt {
		return "", false
	}
	return cached.Token, true
}

func saveCachedToken(token string, expiresIn int) {
	cached := cachedTokenFile{
		Token:     token,
		ExpiresAt: time.Now().Add(time.Duration(expiresIn-60) * time.Second).Unix(),
	}
	data, _ := json.Marshal(cached)
	os.WriteFile(tokenCachePath(), data, 0600)
}

func getAccessToken() (string, error) {
	if token, ok := loadCachedToken(); ok {
		return token, nil
	}

	clientID := getEnv("CLOVER_CLIENT_ID", "CLAUDE_PLUGIN_OPTION_CLIENT_ID")
	clientSecret := getEnv("CLOVER_CLIENT_SECRET", "CLAUDE_PLUGIN_OPTION_CLIENT_SECRET")

	if clientID == "" || clientSecret == "" {
		return "", fmt.Errorf("missing client_id or client_secret")
	}

	authURL := getAuthURL() + "/identity/resources/auth/v1/api-token"

	body, _ := json.Marshal(map[string]string{
		"clientId": clientID,
		"secret":   clientSecret,
	})

	resp, err := httpClient().Post(authURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("auth request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("auth returned %d: %s", resp.StatusCode, string(respBody))
	}

	var tokenResp tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("auth response parse error: %w", err)
	}

	saveCachedToken(tokenResp.AccessToken, tokenResp.ExpiresIn)

	logMsg(fmt.Sprintf("token acquired, expires in %ds", tokenResp.ExpiresIn))
	return tokenResp.AccessToken, nil
}

// --- Models ---

type hookInput struct {
	SessionID string    `json:"session_id"`
	CWD       string    `json:"cwd"`
	HookEvent string    `json:"hook_event_name"`
	ToolName  string    `json:"tool_name"`
	ToolInput toolInput `json:"tool_input"`
}

type toolInput struct {
	Plan         string `json:"plan"`
	PlanFilePath string `json:"planFilePath"`
}

type reviewRequest struct {
	Plan      string `json:"plan"`
	PlanFile  string `json:"plan_file"`
	Repo      string `json:"repo"`
	Branch    string `json:"branch"`
	User      string `json:"user"`
	Email     string `json:"email"`
	SessionID string `json:"session_id"`
}

type reviewResponse struct {
	Approved bool   `json:"approved"`
	Reason   string `json:"reason"`
}

type logPromptRequest struct {
	Prompt string `json:"prompt"`
	User   string `json:"user"`
	Email  string `json:"email"`
	Repo   string `json:"repo"`
	Branch string `json:"branch"`
}

// --- Helpers ---

func allowJSON() string {
	return `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}`
}

func denyJSON(reason string) string {
	output := map[string]interface{}{
		"hookSpecificOutput": map[string]interface{}{
			"hookEventName":            "PreToolUse",
			"permissionDecision":       "deny",
			"permissionDecisionReason": reason,
		},
	}
	b, _ := json.Marshal(output)
	return string(b)
}

func getEnv(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

func getClaudeEmail() string {
	cmd := exec.Command("claude", "auth", "status", "--json")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	var result struct {
		Email string `json:"email"`
	}
	if json.Unmarshal(out, &result) == nil {
		return result.Email
	}
	return ""
}

func gitCmd(dir string, args ...string) string {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

func httpClient() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Minute,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

func postJSON(url, token string, body interface{}) ([]byte, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func getServerURL() string {
	url := getEnv("CLOVER_SERVER_URL", "CLAUDE_PLUGIN_OPTION_SERVER_URL")
	if url == "" {
		return "https://app.cloversec.io"
	}
	return strings.TrimRight(url, "/")
}

// --- Handlers ---

func handleReviewPlan(input []byte) {
	var hook hookInput
	if err := json.Unmarshal(input, &hook); err != nil {
		logMsg(fmt.Sprintf("allow (parse error: %v)", err))
		fmt.Println(allowJSON())
		return
	}

	plan := hook.ToolInput.Plan
	logMsg(fmt.Sprintf("--- session=%s plan=%dchars file=%s", hook.SessionID, len(plan), hook.ToolInput.PlanFilePath))

	if plan == "" {
		logMsg("allow (no plan)")
		fmt.Println(allowJSON())
		return
	}

	token, err := getAccessToken()
	if err != nil {
		logMsg(fmt.Sprintf("allow (auth failed: %v)", err))
		fmt.Println(allowJSON())
		return
	}

	serverURL := getServerURL()

	cwd := hook.CWD
	if cwd == "" {
		cwd = "."
	}

	body := reviewRequest{
		Plan:      plan,
		PlanFile:  hook.ToolInput.PlanFilePath,
		Repo:      filepath.Base(gitCmd(cwd, "rev-parse", "--show-toplevel")),
		Branch:    gitCmd(cwd, "branch", "--show-current"),
		User:      gitCmd(cwd, "config", "user.name"),
		Email:     getClaudeEmail(),
		SessionID: hook.SessionID,
	}

	start := time.Now()
	respBody, err := postJSON(serverURL+"/Hooks/ReviewPlan", token, body)
	elapsed := time.Since(start).Seconds()

	if err != nil {
		logMsg(fmt.Sprintf("allow (server unreachable %.0fs: %v)", elapsed, err))
		fmt.Println(allowJSON())
		return
	}

	var resp reviewResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		logMsg(fmt.Sprintf("allow (bad response: %v)", err))
		fmt.Println(allowJSON())
		return
	}

	logMsg(fmt.Sprintf("result: approved=%v %.0fs", resp.Approved, elapsed))

	if resp.Approved {
		fmt.Println(allowJSON())
	} else {
		logMsg(fmt.Sprintf("deny (%d chars)", len(resp.Reason)))
		fmt.Println(denyJSON(resp.Reason))
	}
}

func handleLogPrompt(input []byte) {
	token, err := getAccessToken()
	if err != nil {
		logMsg(fmt.Sprintf("log-prompt: auth failed: %v", err))
		return
	}

	serverURL := getServerURL()

	var raw map[string]interface{}
	if err := json.Unmarshal(input, &raw); err != nil {
		logMsg(fmt.Sprintf("log-prompt: parse error: %v", err))
		return
	}

	cwd, _ := raw["cwd"].(string)
	if cwd == "" {
		cwd = "."
	}

	prompt := fmt.Sprintf("%v", raw["prompt"])
	body := logPromptRequest{
		Prompt: prompt,
		User:   gitCmd(cwd, "config", "user.name"),
		Email:  getClaudeEmail(),
		Repo:   filepath.Base(gitCmd(cwd, "rev-parse", "--show-toplevel")),
		Branch: gitCmd(cwd, "branch", "--show-current"),
	}

	logMsg(fmt.Sprintf("log-prompt: %dchars → %s", len(prompt), serverURL))
	_, err = postJSON(serverURL+"/Hooks/LogPrompt", token, body)
	if err != nil {
		logMsg(fmt.Sprintf("log-prompt: POST failed: %v", err))
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: clover-hook <review-plan|log-prompt>")
		os.Exit(1)
	}

	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to read stdin:", err)
		os.Exit(1)
	}

	switch os.Args[1] {
	case "review-plan":
		handleReviewPlan(input)
	case "log-prompt":
		handleLogPrompt(input)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}
