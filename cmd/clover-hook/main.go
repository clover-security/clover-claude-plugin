// Package main implements the clover-hook binary — a Claude Code plugin hook
// that intercepts plan-mode exits and runs a server-side security review before
// allowing the agent to proceed.
//
// # How it works
//
// Claude Code calls this binary at two points during a session:
//
//  1. PreToolUse on ExitPlanMode — the agent is about to leave plan mode and
//     start implementing. The hook sends the plan to the Clover server for a
//     security review. If the server finds unaddressed MUST requirements, the
//     hook returns "deny" and Claude Code blocks the action, showing the
//     developer the missing security items.
//
//  2. UserPromptSubmit — the user submitted a prompt. The hook forwards it to
//     the server for audit logging (fire-and-forget, never blocks).
//
// # Review flow
//
// Because security analysis can take 20–30 seconds (entity resolution, LLM
// calls), the review uses an async pattern:
//
//  POST /Hooks/ReviewPlan  { plan, repo, branch, sessionId }
//       → { taskId }                       (analysis queued, poll for result)
//
//  POST /Hooks/PollReview  { sessionId, taskId }
//       → { taskId }                       (still processing, wait and retry)
//       → { approved, reason }             (final verdict)
//
// If the server is unreachable or the review times out, the hook always
// approves — it never blocks work due to infrastructure issues.
//
// # Session model
//
// The server tracks a session (keyed by Claude Code's session_id) across
// multiple plan reviews. The first review fetches and classifies security
// requirements; subsequent reviews in the same session only judge whether the
// updated plan addresses the previously identified MUST requirements. After
// 4 reviews or a passing verdict the session is cleared.
//
// # Configuration
//
// The binary is configured via environment variables, typically set by the
// Claude Code plugin framework:
//
//	CLOVER_CLIENT_ID / CLAUDE_PLUGIN_OPTION_CLIENT_ID       — Frontegg API client ID
//	CLOVER_CLIENT_SECRET / CLAUDE_PLUGIN_OPTION_CLIENT_SECRET — Frontegg API secret
//	CLOVER_SERVER_URL / CLAUDE_PLUGIN_OPTION_SERVER_URL     — Clover API base URL (default: https://app.cloversec.io)
//	CLOVER_AUTH_URL / CLAUDE_PLUGIN_OPTION_AUTH_URL         — Frontegg auth URL (default: https://clover.frontegg.com)
//	CLAUDE_PLUGIN_DATA                                       — directory for caching the auth token
//
// # Debugging
//
// All activity is appended to /tmp/clover-hook.log with timestamps.
// To force a fresh auth token, delete the cached token file:
//
//	rm /tmp/clover-token.json            # default location
//	rm $CLAUDE_PLUGIN_DATA/token.json    # if CLAUDE_PLUGIN_DATA is set
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

// logFile is the path where all hook activity is written for debugging.
const logFile = "/tmp/clover-hook.log"

// logMsg appends a timestamped message to the log file. Errors writing to the
// log are silently ignored so the hook never fails due to logging issues.
func logMsg(msg string) {
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "[%s] %s\n", time.Now().Format("15:04:05"), msg)
}

// =============================================================================
// Auth — Frontegg API token exchange and file-based caching
// =============================================================================

// tokenResponse is the JSON body returned by the Frontegg token endpoint.
type tokenResponse struct {
	AccessToken string `json:"accessToken"`
	ExpiresIn   int    `json:"expiresIn"`
	TokenType   string `json:"tokenType"`
}

// cachedTokenFile is the structure persisted to disk to avoid re-authenticating
// on every hook invocation.
type cachedTokenFile struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"` // Unix timestamp; token is refreshed 60s early
}

// getAuthURL returns the Frontegg base URL, configurable via environment.
func getAuthURL() string {
	authURL := getEnv("CLOVER_AUTH_URL", "CLAUDE_PLUGIN_OPTION_AUTH_URL")
	if authURL == "" {
		return "https://clover.frontegg.com"
	}
	return strings.TrimRight(authURL, "/")
}

// tokenCachePath returns the path to the cached token file.
// Defaults to /tmp/clover-token.json unless CLAUDE_PLUGIN_DATA is set.
func tokenCachePath() string {
	dataDir := getEnv("CLAUDE_PLUGIN_DATA")
	if dataDir == "" {
		return "/tmp/clover-token.json"
	}
	return filepath.Join(dataDir, "token.json")
}

// loadCachedToken reads the cached token from disk and returns it if it has
// not expired. Returns ("", false) if the file is missing, invalid, or stale.
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

// saveCachedToken writes the token to disk with an expiry 60 seconds before
// the server-reported expiry to avoid using a token that is about to expire.
func saveCachedToken(token string, expiresIn int) {
	cached := cachedTokenFile{
		Token:     token,
		ExpiresAt: time.Now().Add(time.Duration(expiresIn-60) * time.Second).Unix(),
	}
	data, _ := json.Marshal(cached)
	os.WriteFile(tokenCachePath(), data, 0600)
}

// getAccessToken returns a valid Frontegg API token, using the disk cache when
// possible. On cache miss it exchanges the client credentials for a new token
// and saves it. Returns an error if credentials are missing or auth fails.
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

// =============================================================================
// Request / response models
// =============================================================================

// hookInput is the JSON payload Claude Code sends to the hook binary on stdin.
type hookInput struct {
	SessionID string    `json:"session_id"`  // unique ID for this Claude Code session
	CWD       string    `json:"cwd"`         // working directory of the Claude Code process
	HookEvent string    `json:"hook_event_name"`
	ToolName  string    `json:"tool_name"`
	ToolInput toolInput `json:"tool_input"`
}

// toolInput carries the plan text written by the agent when exiting plan mode.
type toolInput struct {
	Plan         string `json:"plan"`
	PlanFilePath string `json:"planFilePath"`
}

// reviewRequest is sent to POST /Hooks/ReviewPlan to start a security review.
// Only sent once per review attempt — subsequent status checks use pollRequest.
type reviewRequest struct {
	Plan      string `json:"plan"`       // full plan text
	PlanFile  string `json:"plan_file"`  // path to plan file, if any
	Repo      string `json:"repo"`       // git repository name
	Branch    string `json:"branch"`     // current git branch
	User      string `json:"user"`       // git user.name
	Email     string `json:"email"`      // Claude Code authenticated user email
	SessionID string `json:"sessionId"`  // Claude Code session ID
}

// pollRequest is sent to POST /Hooks/PollReview to check whether a previously
// queued review has completed. Much smaller than reviewRequest — no plan text.
type pollRequest struct {
	SessionID string `json:"sessionId"`
	TaskID    string `json:"taskId"`
}

// reviewResponse is returned by both /Hooks/ReviewPlan and /Hooks/PollReview.
//
//   - TaskID non-empty → analysis is still running; poll again after a short wait.
//   - TaskID empty, Approved true → plan passed security review; proceed.
//   - TaskID empty, Approved false → plan has unaddressed MUST requirements;
//     Reason contains a human-readable list to show the developer.
type reviewResponse struct {
	Approved bool   `json:"approved"`
	Reason   string `json:"reason"`
	TaskID   string `json:"taskId"`
}

// logPromptRequest is sent to POST /Hooks/LogPrompt for audit purposes.
// This call is fire-and-forget and never blocks the user.
type logPromptRequest struct {
	Prompt string `json:"prompt"`
	User   string `json:"user"`
	Email  string `json:"email"`
	Repo   string `json:"repo"`
	Branch string `json:"branch"`
}

// =============================================================================
// Claude Code hook output helpers
// =============================================================================

// allowJSON returns the JSON payload that tells Claude Code to allow the action.
func allowJSON() string {
	return `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}`
}

// denyJSON returns the JSON payload that tells Claude Code to block the action
// and display reason to the developer.
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

// =============================================================================
// Utility helpers
// =============================================================================

// getEnv returns the value of the first environment variable in keys that is
// non-empty, or "" if none are set. Supports fallback keys for compatibility.
func getEnv(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

// getClaudeEmail returns the email of the Claude Code authenticated user by
// running `claude auth status --json`. Returns "" if the command fails.
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

// gitCmd runs a git command in the given directory and returns trimmed stdout.
// Returns "unknown" if the command fails.
func gitCmd(dir string, args ...string) string {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

// httpClient returns an HTTP client with a 5-minute timeout. TLS verification
// is disabled to support self-signed certs in local/staging environments.
func httpClient() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Minute,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

// postJSON marshals body as JSON, POSTs it to url with a Bearer token header,
// and returns the response body. Returns an error for non-2xx status codes.
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
	body2, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body2))
	}
	return body2, nil
}

// getServerURL returns the Clover API base URL, configurable via environment.
func getServerURL() string {
	url := getEnv("CLOVER_SERVER_URL", "CLAUDE_PLUGIN_OPTION_SERVER_URL")
	if url == "" {
		return "https://app.cloversec.io"
	}
	return strings.TrimRight(url, "/")
}

// =============================================================================
// Hook handlers
// =============================================================================

// handleReviewPlan is called when Claude Code fires the PreToolUse hook on
// ExitPlanMode. It sends the plan to the Clover server for security review and
// writes an allow or deny decision to stdout.
//
// The review is async: the first call returns a taskId; subsequent calls to
// /Hooks/PollReview check progress until a final verdict is returned. Polling
// runs for up to 4 minutes (time-based deadline). The pending counter only
// increments on confirmed "still processing" responses from the server, not on
// network errors. The hook always allows on timeout or unreachable server — it
// is a best-effort gate and must never block work due to infrastructure issues.
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

	base := reviewRequest{
		Plan:      plan,
		PlanFile:  hook.ToolInput.PlanFilePath,
		Repo:      filepath.Base(gitCmd(cwd, "rev-parse", "--show-toplevel")),
		Branch:    gitCmd(cwd, "branch", "--show-current"),
		User:      gitCmd(cwd, "config", "user.name"),
		Email:     getClaudeEmail(),
		SessionID: hook.SessionID,
	}

	const pollInterval = 3 * time.Second
	const maxWait = 4 * time.Minute

	start := time.Now()
	deadline := start.Add(maxWait)

	// Start the review — sends the full plan once.
	respBody, err := postJSON(serverURL+"/Hooks/ReviewPlan", token, base)
	if err != nil {
		logMsg(fmt.Sprintf("allow (server unreachable %.0fs: %v)", time.Since(start).Seconds(), err))
		fmt.Println(allowJSON())
		return
	}

	var resp reviewResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		logMsg(fmt.Sprintf("allow (bad response: %v)", err))
		fmt.Println(allowJSON())
		return
	}

	// Poll until the server returns a final verdict (TaskID becomes empty).
	// pendingCount tracks confirmed "still processing" responses from the server
	// — it only increments when the server explicitly says the task is pending,
	// not on network errors or retries. The hard limit is the time deadline.
	for pendingCount := 0; resp.TaskID != ""; pendingCount++ {
		elapsed := time.Since(start)
		if time.Now().After(deadline) {
			logMsg(fmt.Sprintf("allow (poll timeout after %d pending responses, %.0fs)", pendingCount, elapsed.Seconds()))
			fmt.Println(allowJSON())
			return
		}
		logMsg(fmt.Sprintf("pending task=%s count=%d elapsed=%.0fs remaining=%.0fs",
			resp.TaskID, pendingCount, elapsed.Seconds(), time.Until(deadline).Seconds()))
		time.Sleep(pollInterval)

		pollBody := pollRequest{SessionID: hook.SessionID, TaskID: resp.TaskID}
		respBody, err = postJSON(serverURL+"/Hooks/PollReview", token, pollBody)
		if err != nil {
			logMsg(fmt.Sprintf("allow (server unreachable %.0fs: %v)", time.Since(start).Seconds(), err))
			fmt.Println(allowJSON())
			return
		}
		resp = reviewResponse{}
		if err := json.Unmarshal(respBody, &resp); err != nil {
			logMsg(fmt.Sprintf("allow (bad response: %v)", err))
			fmt.Println(allowJSON())
			return
		}
	}

	logMsg(fmt.Sprintf("result: approved=%v %.0fs", resp.Approved, time.Since(start).Seconds()))
	if resp.Approved {
		fmt.Println(allowJSON())
	} else {
		logMsg(fmt.Sprintf("deny (%d chars)", len(resp.Reason)))
		fmt.Println(denyJSON(resp.Reason))
	}
}

// handleLogPrompt is called when Claude Code fires the UserPromptSubmit hook.
// It forwards the prompt to the Clover server for audit logging. This call is
// fire-and-forget — failures are logged but never surface to the developer.
func handleLogPrompt(input []byte) {
	// Log all CLAUDE_PLUGIN_* env vars at debug level to help with configuration issues.
	for _, env := range os.Environ() {
		if strings.HasPrefix(env, "CLAUDE_PLUGIN") {
			logMsg(fmt.Sprintf("env: %s", env))
		}
	}

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

// =============================================================================
// Entry point
// =============================================================================

// main reads the hook event from stdin and dispatches to the appropriate
// handler based on the command-line argument:
//
//	clover-hook review-plan   — called on ExitPlanMode (PreToolUse)
//	clover-hook log-prompt    — called on UserPromptSubmit
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
