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
	"regexp"
	"strings"
	"time"
)

// skipMarkerRegex finds [SKIP:N — reason] markers anywhere in the plan text,
// not just on lines that start with "[SKIP:". Claude often inlines the marker
// inside a bullet or sentence, so we match across the whole plan.
//   - `\[SKIP:`        — literal opening
//   - `\s*\d+`         — the 1-based requirement index, tolerant of whitespace
//   - `[^\]]*`         — anything up to the closing bracket (the reason)
//   - `\]`             — literal closing
var skipMarkerRegex = regexp.MustCompile(`\[SKIP:\s*\d+[^\]]*\]`)

// logFile is the path where all hook activity is written for debugging.
const logFile = "/tmp/clover-hook.log"

// logMsg appends a timestamped INFO-level message to the log file. Errors
// writing to the log are silently ignored so the hook never fails due to
// logging issues. See logf for level + structured key=value logging.
func logMsg(msg string) {
	logf("INFO", "%s", msg)
}

// logf is the structured-logging primitive. Prefer it over logMsg when adding
// new logs: pass a level (INFO/WARN/ERROR/DEBUG) and a key=value formatted
// message so the log is greppable (e.g. `grep 'session=abc' /tmp/clover-hook.log`).
func logf(level string, format string, args ...any) {
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "[%s] [%s] [pid=%d] %s\n",
		time.Now().Format("2006-01-02 15:04:05.000"),
		level,
		os.Getpid(),
		fmt.Sprintf(format, args...))
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

// sessionState holds classified security requirements returned by the server
// after analysis completes. The plugin stores it and echoes it back on every
// subsequent ReviewPlan call so the server can remain stateless.
//
// CodingPlanId is the server-side identifier for the persisted coding_plan row.
// It MUST be round-tripped verbatim — the server uses it to look up the plan
// and write its final Approved/Denied status. Dropping this field here means
// every follow-up round looks like a brand-new session to the database.
//
// LastPlan + LastDenyReason are plugin-local fields (the server never sees
// them). They enable the "plan unchanged → short-circuit" optimization: if the
// agent triggers ExitPlanMode with the same plan text we already judged, we
// re-emit the previous deny reason without calling the server and without
// bumping the server's review counter. This prevents repeated identical
// submissions from eventually tripping the server's max-reviews auto-approve.
type sessionState struct {
	CodingPlanId   string   `json:"codingPlanId,omitempty"`
	LastDenyReason string   `json:"lastDenyReason,omitempty"`
	LastPlan       string   `json:"lastPlan,omitempty"`
	Must           []string `json:"must"`
	Optional       []string `json:"optional,omitempty"`
	ReviewCount    int      `json:"reviewCount"`
}

// parseSkipLines extracts every [SKIP:N — reason] marker from the plan text,
// regardless of whether it sits on its own line or inline inside a bullet or
// sentence. The server is responsible for parsing the index and reason — the
// plugin just forwards the raw marker strings.
func parseSkipLines(plan string) []string {
	matches := skipMarkerRegex.FindAllString(plan, -1)
	if matches == nil {
		return nil
	}
	return matches
}

// reviewRequest is sent to POST /Hooks/ReviewPlan to start or continue a review.
// SessionState is omitted on the first call; the server returns it after analysis
// and the plugin includes it on all subsequent calls.
type reviewRequest struct {
	Plan         string        `json:"plan"`                   // full plan text
	PlanFile     string        `json:"plan_file"`              // path to plan file, if any
	Repo         string        `json:"repo"`                   // git repository name
	Branch       string        `json:"branch"`                 // current git branch
	User         string        `json:"user"`                   // git user.name
	Email        string        `json:"email"`                  // Claude Code authenticated user email
	SessionID    string        `json:"sessionId"`              // Claude Code session ID
	SessionState *sessionState `json:"sessionState,omitempty"` // echoed from previous response
	SkipLines    []string      `json:"skipLines,omitempty"`    // raw [SKIP:N — reason] lines from plan
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
//   - SessionState non-nil → store and echo back on the next ReviewPlan call.
type reviewResponse struct {
	Approved     bool          `json:"approved"`
	Reason       string        `json:"reason"`
	SessionState *sessionState `json:"sessionState,omitempty"`
	TaskID       string        `json:"taskId"`
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

// sessionStatePath returns the path for persisting sessionState between hook
// invocations. Each ExitPlanMode event spawns a fresh binary, so we persist
// to disk keyed by sessionId.
func sessionStatePath(sessionId string) string {
	dataDir := getEnv("CLAUDE_PLUGIN_DATA")
	if dataDir == "" {
		dataDir = os.TempDir()
	}
	return filepath.Join(dataDir, "clover-session-"+sessionId+".json")
}

// loadSessionState reads persisted sessionState from disk for this session.
// Returns nil if the file doesn't exist or is invalid.
func loadSessionState(sessionId string) *sessionState {
	path := sessionStatePath(sessionId)
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			logf("WARN", "session_state read failed path=%s err=%v", path, err)
		}
		return nil
	}
	var state sessionState
	if err := json.Unmarshal(data, &state); err != nil {
		logf("WARN", "session_state unmarshal failed path=%s bytes=%d err=%v", path, len(data), err)
		return nil
	}
	logf("DEBUG", "session_state loaded path=%s bytes=%d review_count=%d", path, len(data), state.ReviewCount)
	return &state
}

// saveSessionState persists sessionState to disk so the next hook invocation
// for this session can pick it up.
func saveSessionState(sessionId string, state *sessionState) {
	path := sessionStatePath(sessionId)
	data, _ := json.Marshal(state)
	if err := os.WriteFile(path, data, 0600); err != nil {
		logf("WARN", "session_state write failed path=%s err=%v", path, err)
		return
	}
	logf("DEBUG", "session_state written path=%s bytes=%d", path, len(data))
}

// clearSessionState removes the persisted sessionState file when the session
// is approved or exhausted.
func clearSessionState(sessionId string) {
	path := sessionStatePath(sessionId)
	if err := os.Remove(path); err != nil {
		if !os.IsNotExist(err) {
			logf("WARN", "session_state remove failed path=%s err=%v", path, err)
		}
		return
	}
	logf("DEBUG", "session_state removed path=%s", path)
}

// requirementsFilePath returns the path of the sidecar requirements file
// written next to the agent's plan file. When the plan is at
// /path/to/plan.md, the requirements go to /path/to/plan.clover-requirements.md.
// If the plan file is unknown we fall back to $CLAUDE_PLUGIN_DATA so the file
// still persists across hook invocations keyed by sessionId.
func requirementsFilePath(planFile, sessionId string) string {
	if planFile != "" {
		dir := filepath.Dir(planFile)
		base := filepath.Base(planFile)
		ext := filepath.Ext(base)
		stem := strings.TrimSuffix(base, ext)
		return filepath.Join(dir, stem+".clover-requirements.md")
	}
	dataDir := getEnv("CLAUDE_PLUGIN_DATA")
	if dataDir == "" {
		dataDir = os.TempDir()
	}
	return filepath.Join(dataDir, "clover-requirements-"+sessionId+".md")
}

// writeRequirementsFile persists the deny reason (which contains the MUST
// requirements and skip instructions) next to the plan file. This gives the
// agent a stable, file-based reference of what it must address on the next
// pass — more robust than relying on the [SKIP:N] markers surviving a plan
// rewrite.
func writeRequirementsFile(planFile, sessionId, reason string) {
	path := requirementsFilePath(planFile, sessionId)
	if err := os.WriteFile(path, []byte(reason+"\n"), 0600); err != nil {
		logf("WARN", "sidecar write failed path=%s err=%v", path, err)
	}
}

// clearRequirementsFile removes the sidecar requirements file on approval.
func clearRequirementsFile(planFile, sessionId string) {
	path := requirementsFilePath(planFile, sessionId)
	if err := os.Remove(path); err != nil {
		if !os.IsNotExist(err) {
			logf("WARN", "sidecar remove failed path=%s err=%v", path, err)
		}
		return
	}
	logf("DEBUG", "sidecar removed path=%s", path)
}

// handleReviewPlan is called when Claude Code fires the PreToolUse hook on
// ExitPlanMode. Each invocation is a fresh process — sessionState is persisted
// to disk between invocations so the server can judge updated plans against the
// original requirements instead of re-analyzing from scratch.
//
// Flow across multiple ExitPlanMode events:
//
//  1st invocation (no persisted state):
//    → POST /Hooks/ReviewPlan {plan} → {taskId} → poll → {denied, sessionState}
//    → persist sessionState to disk → return deny to Claude
//
//  2nd invocation (persisted state found):
//    → load sessionState from disk → parse [SKIP:N] markers from plan
//    → POST /Hooks/ReviewPlan {plan, sessionState} → {approved/denied}
//    → if denied: update persisted state → return deny
//    → if approved: clear persisted state → return allow
func handleReviewPlan(input []byte) {
	logf("INFO", "=== review_plan hook fired input_size=%d", len(input))

	var hook hookInput
	if err := json.Unmarshal(input, &hook); err != nil {
		logf("ERROR", "action=allow reason=parse_error err=%v", err)
		fmt.Println(allowJSON())
		return
	}

	plan := hook.ToolInput.Plan
	logf("INFO", "session=%s plan_chars=%d plan_file=%q cwd=%q",
		hook.SessionID, len(plan), hook.ToolInput.PlanFilePath, hook.CWD)

	if plan == "" {
		logf("INFO", "action=allow reason=empty_plan session=%s", hook.SessionID)
		fmt.Println(allowJSON())
		return
	}

	token, err := getAccessToken()
	if err != nil {
		logf("ERROR", "action=allow reason=auth_failed session=%s err=%v", hook.SessionID, err)
		fmt.Println(allowJSON())
		return
	}
	logf("DEBUG", "auth ok session=%s", hook.SessionID)

	serverURL := getServerURL()
	logf("DEBUG", "server_url=%s session=%s", serverURL, hook.SessionID)

	cwd := hook.CWD
	if cwd == "" {
		cwd = "."
	}

	req := reviewRequest{
		Plan:      plan,
		PlanFile:  hook.ToolInput.PlanFilePath,
		Repo:      filepath.Base(gitCmd(cwd, "rev-parse", "--show-toplevel")),
		Branch:    gitCmd(cwd, "branch", "--show-current"),
		User:      gitCmd(cwd, "config", "user.name"),
		Email:     getClaudeEmail(),
		SessionID: hook.SessionID,
	}
	logf("INFO", "git repo=%q branch=%q user=%q email=%q session=%s",
		req.Repo, req.Branch, req.User, req.Email, hook.SessionID)

	// Load persisted sessionState from a previous invocation (if any).
	// If found, include it so the server judges instead of re-analyzing.
	// Raw [SKIP:N] lines are sent separately for the server to parse.
	persisted := loadSessionState(hook.SessionID)

	if persisted != nil {
		// Short-circuit: if the plan text is identical to the last round we
		// already denied, re-emit the cached deny reason without a server call
		// and without bumping the review counter. Removes the "repeat the same
		// plan until the server auto-approves" escape hatch; responsive when
		// the agent triggers ExitPlanMode with no edits.
		if persisted.LastPlan != "" && persisted.LastPlan == plan && persisted.LastDenyReason != "" {
			logf("INFO", "short_circuit plan_unchanged review_count=%d session=%s — re-deny from cache",
				persisted.ReviewCount, hook.SessionID)
			fmt.Println(denyJSON(persisted.LastDenyReason))
			return
		}

		skipLines := parseSkipLines(plan)
		logf("INFO", "flow=judge persisted_state review_count=%d must=%d optional=%d skips_found=%d session=%s",
			persisted.ReviewCount, len(persisted.Must), len(persisted.Optional), len(skipLines), hook.SessionID)
		for i, skip := range skipLines {
			logf("DEBUG", "skip_marker[%d]=%q session=%s", i, skip, hook.SessionID)
		}
		req.SessionState = persisted
		req.SkipLines = skipLines
	} else {
		logf("INFO", "flow=start no_persisted_state session=%s", hook.SessionID)
	}

	const pollInterval = 3 * time.Second
	const maxWait = 3 * time.Minute

	start := time.Now()
	deadline := start.Add(maxWait)

	// Send the review request.
	logf("DEBUG", "POST %s/Hooks/ReviewPlan session=%s", serverURL, hook.SessionID)
	respBody, err := postJSON(serverURL+"/Hooks/ReviewPlan", token, req)
	if err != nil {
		logf("ERROR", "action=allow reason=server_unreachable elapsed=%.1fs session=%s err=%v",
			time.Since(start).Seconds(), hook.SessionID, err)
		fmt.Println(allowJSON())
		return
	}
	logf("DEBUG", "review response bytes=%d elapsed=%.1fs session=%s",
		len(respBody), time.Since(start).Seconds(), hook.SessionID)

	var resp reviewResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		logf("ERROR", "action=allow reason=bad_response session=%s err=%v", hook.SessionID, err)
		fmt.Println(allowJSON())
		return
	}

	// Poll until the work item completes (only happens on first review when
	// there's no persisted state — follow-up reviews are synchronous).
	for pendingCount := 0; resp.TaskID != ""; pendingCount++ {
		if time.Now().After(deadline) {
			logf("WARN", "action=allow reason=poll_timeout polls=%d elapsed=%.1fs session=%s task=%s",
				pendingCount, time.Since(start).Seconds(), hook.SessionID, resp.TaskID)
			fmt.Println(allowJSON())
			return
		}
		logf("INFO", "poll pending task=%s count=%d elapsed=%.1fs remaining=%.1fs session=%s",
			resp.TaskID, pendingCount, time.Since(start).Seconds(), time.Until(deadline).Seconds(), hook.SessionID)
		time.Sleep(pollInterval)

		pollBody := pollRequest{SessionID: hook.SessionID, TaskID: resp.TaskID}
		respBody, err = postJSON(serverURL+"/Hooks/PollReview", token, pollBody)
		if err != nil {
			logf("ERROR", "action=allow reason=server_unreachable_on_poll elapsed=%.1fs session=%s err=%v",
				time.Since(start).Seconds(), hook.SessionID, err)
			fmt.Println(allowJSON())
			return
		}
		resp = reviewResponse{}
		if err := json.Unmarshal(respBody, &resp); err != nil {
			logf("ERROR", "action=allow reason=bad_poll_response session=%s err=%v", hook.SessionID, err)
			fmt.Println(allowJSON())
			return
		}
	}

	// Log the final verdict details before acting on it.
	mustCount, optCount := 0, 0
	if resp.SessionState != nil {
		mustCount = len(resp.SessionState.Must)
		optCount = len(resp.SessionState.Optional)
	}
	logf("INFO", "verdict approved=%t reason_chars=%d must=%d optional=%d review_count=%d elapsed=%.1fs session=%s",
		resp.Approved, len(resp.Reason), mustCount, optCount,
		func() int {
			if resp.SessionState != nil {
				return resp.SessionState.ReviewCount
			}
			return 0
		}(),
		time.Since(start).Seconds(), hook.SessionID)

	// Persist or clear sessionState for the next hook invocation.
	if resp.Approved {
		clearSessionState(hook.SessionID)
		clearRequirementsFile(hook.ToolInput.PlanFilePath, hook.SessionID)
		logf("INFO", "action=allow reason=approved session_state_cleared sidecar_cleared elapsed=%.1fs session=%s",
			time.Since(start).Seconds(), hook.SessionID)
		fmt.Println(allowJSON())
	} else {
		// Persist state: keep Must from the first classification (persisted or
		// newly received), only update ReviewCount.
		if resp.SessionState != nil {
			stateToSave := resp.SessionState
			if persisted != nil {
				// Keep original Must/Optional + CodingPlanId, only take updated ReviewCount.
				// CodingPlanId MUST be preserved across rounds so the server can write
				// the final Approved/Denied status on the correct coding_plan row.
				stateToSave = &sessionState{
					CodingPlanId: persisted.CodingPlanId,
					Must:         persisted.Must,
					Optional:     persisted.Optional,
					ReviewCount:  resp.SessionState.ReviewCount,
				}
				logf("DEBUG", "preserving original must=%d optional=%d coding_plan_id=%s from persisted state session=%s",
					len(persisted.Must), len(persisted.Optional), persisted.CodingPlanId, hook.SessionID)
			}
			// Record this round's plan + deny reason so the next invocation can
			// short-circuit if the agent resubmits the same plan verbatim.
			stateToSave.LastPlan = plan
			stateToSave.LastDenyReason = resp.Reason
			saveSessionState(hook.SessionID, stateToSave)
			logf("INFO", "persisted session_state path=%s review_count=%d must=%d session=%s",
				sessionStatePath(hook.SessionID), stateToSave.ReviewCount, len(stateToSave.Must), hook.SessionID)
		} else {
			logf("WARN", "deny response had no sessionState — subsequent reviews will restart session=%s", hook.SessionID)
		}
		// Write the deny reason (requirements + skip instructions) next to the
		// plan file so the agent can reference it reliably on the next pass —
		// more robust than hoping [SKIP:N] markers survive a plan rewrite.
		sidecar := requirementsFilePath(hook.ToolInput.PlanFilePath, hook.SessionID)
		writeRequirementsFile(hook.ToolInput.PlanFilePath, hook.SessionID, resp.Reason)
		logf("INFO", "sidecar_written path=%s bytes=%d session=%s",
			sidecar, len(resp.Reason), hook.SessionID)
		logf("INFO", "action=deny reason_chars=%d elapsed=%.1fs session=%s",
			len(resp.Reason), time.Since(start).Seconds(), hook.SessionID)
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
