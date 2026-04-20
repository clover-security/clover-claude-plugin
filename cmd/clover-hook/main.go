// clover-hook is a Claude Code plugin hook that intercepts plan-mode exits and
// runs a server-side security review before the agent starts implementing.
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

// skipMarkerRegex matches [SKIP:N — reason] anywhere in text.
var skipMarkerRegex = regexp.MustCompile(`\[SKIP:\s*\d+[^\]]*\]`)

const logFile = "/tmp/clover-hook.log"

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
// Auth
// =============================================================================

type tokenResponse struct {
	AccessToken string `json:"accessToken"`
	ExpiresIn   int    `json:"expiresIn"`
}

type cachedTokenFile struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
}

func tokenCachePath() string {
	if d := getEnv("CLAUDE_PLUGIN_DATA"); d != "" {
		return filepath.Join(d, "token.json")
	}
	return "/tmp/clover-token.json"
}

func loadCachedToken() (string, bool) {
	data, err := os.ReadFile(tokenCachePath())
	if err != nil {
		return "", false
	}
	var c cachedTokenFile
	if json.Unmarshal(data, &c) != nil || time.Now().Unix() >= c.ExpiresAt {
		return "", false
	}
	return c.Token, true
}

func saveCachedToken(token string, expiresIn int) {
	c := cachedTokenFile{Token: token, ExpiresAt: time.Now().Add(time.Duration(expiresIn-60) * time.Second).Unix()}
	data, _ := json.Marshal(c)
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
	authURL := strings.TrimRight(getEnv("CLOVER_AUTH_URL", "CLAUDE_PLUGIN_OPTION_AUTH_URL"), "/")
	if authURL == "" {
		authURL = "https://clover.frontegg.com"
	}
	body, _ := json.Marshal(map[string]string{"clientId": clientID, "secret": clientSecret})
	resp, err := httpClient().Post(authURL+"/identity/resources/auth/v1/api-token", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("auth request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("auth returned %d: %s", resp.StatusCode, string(b))
	}
	var t tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&t); err != nil {
		return "", fmt.Errorf("auth parse error: %w", err)
	}
	saveCachedToken(t.AccessToken, t.ExpiresIn)
	logf("DEBUG", "token acquired expires_in=%ds", t.ExpiresIn)
	return t.AccessToken, nil
}

// =============================================================================
// Models
// =============================================================================

type hookInput struct {
	SessionID string    `json:"session_id"`
	CWD       string    `json:"cwd"`
	HookEvent string    `json:"hook_event_name"`
	ToolName  string    `json:"tool_name"`
	ToolInput toolInput `json:"tool_input"`
}

type toolInput struct {
	Plan         string `json:"plan"`
	PlanFilePath string `json:"planFilePath"` // may be absent; we fall back to findPlanFile
}

// sessionState is round-tripped verbatim between plugin invocations and the server.
// LastPlan / LastDenyReason are plugin-local (server ignores them).
type sessionState struct {
	CodingPlanId   string   `json:"codingPlanId,omitempty"`
	LastDenyReason string   `json:"lastDenyReason,omitempty"`
	LastPlan       string   `json:"lastPlan,omitempty"`
	Must           []string `json:"must"`
	Optional       []string `json:"optional,omitempty"`
	ReviewCount    int      `json:"reviewCount"`
}

type reviewRequest struct {
	Plan         string        `json:"plan"`
	PlanFile     string        `json:"planFile,omitempty"`
	Repo         string        `json:"repo"`
	Branch       string        `json:"branch"`
	User         string        `json:"user"`
	Email        string        `json:"email"`
	SessionID    string        `json:"sessionId"`
	SessionState *sessionState `json:"sessionState,omitempty"`
	SkipLines    []string      `json:"skipLines,omitempty"`
}

type pollRequest struct {
	SessionID string `json:"sessionId"`
	TaskID    string `json:"taskId"`
}

type reviewResponse struct {
	Approved     bool          `json:"approved"`
	Reason       string        `json:"reason"`
	SessionState *sessionState `json:"sessionState,omitempty"`
	TaskID       string        `json:"taskId"`
}

// =============================================================================
// Utilities
// =============================================================================

func getEnv(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

func getServerURL() string {
	if u := getEnv("CLOVER_SERVER_URL", "CLAUDE_PLUGIN_OPTION_SERVER_URL"); u != "" {
		return strings.TrimRight(u, "/")
	}
	return "https://app.cloversec.io"
}

func getClaudeEmail() string {
	out, err := exec.Command("claude", "auth", "status", "--json").Output()
	if err != nil {
		return ""
	}
	var r struct{ Email string `json:"email"` }
	json.Unmarshal(out, &r)
	return r.Email
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
		Timeout:   5 * time.Minute,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
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
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(b))
	}
	return b, nil
}

func allowJSON() string {
	return `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}`
}

func denyJSON(reason string) string {
	b, _ := json.Marshal(map[string]interface{}{
		"hookSpecificOutput": map[string]interface{}{
			"hookEventName":            "PreToolUse",
			"permissionDecision":       "deny",
			"permissionDecisionReason": reason,
		},
	})
	return string(b)
}

// =============================================================================
// Session state
// =============================================================================

func sessionStatePath(sessionId string) string {
	d := getEnv("CLAUDE_PLUGIN_DATA")
	if d == "" {
		d = os.TempDir()
	}
	return filepath.Join(d, "clover-session-"+sessionId+".json")
}

func loadSessionState(sessionId string) *sessionState {
	path := sessionStatePath(sessionId)
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			logf("WARN", "session_state read failed path=%s err=%v", path, err)
		}
		return nil
	}
	var s sessionState
	if err := json.Unmarshal(data, &s); err != nil {
		logf("WARN", "session_state unmarshal failed path=%s err=%v", path, err)
		return nil
	}
	logf("DEBUG", "session_state loaded review_count=%d path=%s", s.ReviewCount, path)
	return &s
}

func saveSessionState(sessionId string, state *sessionState) {
	path := sessionStatePath(sessionId)
	data, _ := json.Marshal(state)
	if err := os.WriteFile(path, data, 0600); err != nil {
		logf("WARN", "session_state write failed path=%s err=%v", path, err)
	}
}

func clearSessionState(sessionId string) {
	os.Remove(sessionStatePath(sessionId))
}

// =============================================================================
// Sidecar files
// =============================================================================

// sidecarPath builds {plan-stem}{suffix} next to the plan file, falling back
// to $CLAUDE_PLUGIN_DATA keyed by sessionId when the plan path is unknown.
func sidecarPath(planFile, sessionId, suffix string) string {
	if planFile != "" {
		base := filepath.Base(planFile)
		stem := strings.TrimSuffix(base, filepath.Ext(base))
		return filepath.Join(filepath.Dir(planFile), stem+suffix)
	}
	d := getEnv("CLAUDE_PLUGIN_DATA")
	if d == "" {
		d = os.TempDir()
	}
	return filepath.Join(d, "clover-"+sessionId+suffix)
}

func requirementsFilePath(planFile, sessionId string) string {
	return sidecarPath(planFile, sessionId, ".clover-requirements.md")
}

func skipsFilePath(planFile, sessionId string) string {
	return sidecarPath(planFile, sessionId, ".clover-skips.md")
}

func writeRequirementsFile(planFile, sessionId, reason string) {
	if err := os.WriteFile(requirementsFilePath(planFile, sessionId), []byte(reason+"\n"), 0600); err != nil {
		logf("WARN", "requirements write failed err=%v", err)
	}
}

func clearSidecarFiles(planFile, sessionId string) {
	os.Remove(requirementsFilePath(planFile, sessionId))
	os.Remove(skipsFilePath(planFile, sessionId))
}

// parseSkipLinesFromSidecar reads skip decisions from the dedicated skips file.
// The agent writes [SKIP:N — reason] lines to {plan-stem}.clover-skips.md,
// keeping the plan text and requirements file untouched.
func parseSkipLinesFromSidecar(planFile, sessionId string) []string {
	data, err := os.ReadFile(skipsFilePath(planFile, sessionId))
	if err != nil {
		return nil
	}
	return skipMarkerRegex.FindAllString(string(data), -1)
}

// findPlanFile discovers the plan's on-disk path by scanning ~/.claude/plans/.
// Prefers an exact content match; falls back to the most-recently-modified
// .md file if it was written within the last 60 seconds.
func findPlanFile(plan string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	plansDir := filepath.Join(home, ".claude", "plans")
	entries, err := os.ReadDir(plansDir)
	if err != nil {
		return ""
	}
	norm := strings.TrimSpace(plan)
	var latestInfo os.FileInfo
	var latestPath string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		path := filepath.Join(plansDir, e.Name())
		if data, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(data)) == norm {
			logf("DEBUG", "plan_file content_match path=%s", path)
			return path
		}
		if info, err := e.Info(); err == nil {
			if latestInfo == nil || info.ModTime().After(latestInfo.ModTime()) {
				latestInfo, latestPath = info, path
			}
		}
	}
	if latestInfo != nil && time.Since(latestInfo.ModTime()) < 60*time.Second {
		logf("DEBUG", "plan_file mtime_fallback path=%s", latestPath)
		return latestPath
	}
	return ""
}

// =============================================================================
// Hook handlers
// =============================================================================

func handleReviewPlan(input []byte) {
	logf("INFO", "=== review_plan fired input_size=%d", len(input))

	var hook hookInput
	if err := json.Unmarshal(input, &hook); err != nil {
		logf("ERROR", "action=allow reason=parse_error err=%v", err)
		fmt.Println(allowJSON())
		return
	}

	plan := hook.ToolInput.Plan
	planFilePath := hook.ToolInput.PlanFilePath
	if planFilePath == "" {
		planFilePath = findPlanFile(plan)
	}
	logf("INFO", "session=%s plan_chars=%d plan_file=%q cwd=%q",
		hook.SessionID, len(plan), planFilePath, hook.CWD)

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

	cwd := hook.CWD
	if cwd == "" {
		cwd = "."
	}

	req := reviewRequest{
		Plan:      plan,
		PlanFile:  planFilePath,
		Repo:      filepath.Base(gitCmd(cwd, "rev-parse", "--show-toplevel")),
		Branch:    gitCmd(cwd, "branch", "--show-current"),
		User:      gitCmd(cwd, "config", "user.name"),
		Email:     getClaudeEmail(),
		SessionID: hook.SessionID,
	}
	logf("INFO", "git repo=%q branch=%q user=%q session=%s", req.Repo, req.Branch, req.User, hook.SessionID)

	persisted := loadSessionState(hook.SessionID)

	if persisted != nil {
		// Same plan as last deny — no point calling server again.
		if persisted.LastPlan == plan && persisted.LastDenyReason != "" {
			logf("INFO", "short_circuit plan_unchanged review_count=%d session=%s", persisted.ReviewCount, hook.SessionID)
			fmt.Println(denyJSON(persisted.LastDenyReason))
			return
		}
		skipLines := parseSkipLinesFromSidecar(planFilePath, hook.SessionID)
		logf("INFO", "flow=judge review_count=%d must=%d skips=%d session=%s",
			persisted.ReviewCount, len(persisted.Must), len(skipLines), hook.SessionID)
		req.SessionState = persisted
		req.SkipLines = skipLines
	} else {
		logf("INFO", "flow=start session=%s", hook.SessionID)
	}

	start := time.Now()
	deadline := start.Add(3 * time.Minute)

	respBody, err := postJSON(getServerURL()+"/Hooks/ReviewPlan", token, req)
	if err != nil {
		logf("ERROR", "action=allow reason=server_unreachable session=%s err=%v", hook.SessionID, err)
		fmt.Println(allowJSON())
		return
	}

	var resp reviewResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		logf("ERROR", "action=allow reason=bad_response session=%s err=%v", hook.SessionID, err)
		fmt.Println(allowJSON())
		return
	}

	for pendingCount := 0; resp.TaskID != ""; pendingCount++ {
		if time.Now().After(deadline) {
			logf("WARN", "action=allow reason=poll_timeout polls=%d session=%s", pendingCount, hook.SessionID)
			fmt.Println(allowJSON())
			return
		}
		logf("INFO", "poll task=%s count=%d elapsed=%.1fs session=%s",
			resp.TaskID, pendingCount, time.Since(start).Seconds(), hook.SessionID)
		time.Sleep(3 * time.Second)

		respBody, err = postJSON(getServerURL()+"/Hooks/PollReview", token, pollRequest{hook.SessionID, resp.TaskID})
		if err != nil {
			logf("ERROR", "action=allow reason=poll_unreachable session=%s err=%v", hook.SessionID, err)
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

	mustCount := 0
	if resp.SessionState != nil {
		mustCount = len(resp.SessionState.Must)
	}
	logf("INFO", "verdict approved=%t must=%d elapsed=%.1fs session=%s",
		resp.Approved, mustCount, time.Since(start).Seconds(), hook.SessionID)

	if resp.Approved {
		clearSessionState(hook.SessionID)
		clearSidecarFiles(planFilePath, hook.SessionID)
		logf("INFO", "action=allow reason=approved session=%s", hook.SessionID)
		fmt.Println(allowJSON())
		return
	}

	if resp.SessionState != nil {
		stateToSave := resp.SessionState
		if persisted != nil {
			stateToSave = &sessionState{
				CodingPlanId: persisted.CodingPlanId,
				Must:         persisted.Must,
				Optional:     persisted.Optional,
				ReviewCount:  resp.SessionState.ReviewCount,
			}
		}
		stateToSave.LastPlan = plan
		stateToSave.LastDenyReason = resp.Reason
		saveSessionState(hook.SessionID, stateToSave)
	} else {
		logf("WARN", "deny had no sessionState session=%s", hook.SessionID)
	}
	writeRequirementsFile(planFilePath, hook.SessionID, resp.Reason)
	logf("INFO", "action=deny reason_chars=%d elapsed=%.1fs session=%s",
		len(resp.Reason), time.Since(start).Seconds(), hook.SessionID)
	fmt.Println(denyJSON(resp.Reason))
}

func handleLogPrompt(input []byte) {
	for _, env := range os.Environ() {
		if strings.HasPrefix(env, "CLAUDE_PLUGIN") {
			logf("DEBUG", "env: %s", env)
		}
	}
	token, err := getAccessToken()
	if err != nil {
		logf("WARN", "log-prompt: auth failed: %v", err)
		return
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(input, &raw); err != nil {
		logf("WARN", "log-prompt: parse error: %v", err)
		return
	}
	cwd, _ := raw["cwd"].(string)
	if cwd == "" {
		cwd = "."
	}
	prompt := fmt.Sprintf("%v", raw["prompt"])
	body := struct {
		Prompt string `json:"prompt"`
		User   string `json:"user"`
		Email  string `json:"email"`
		Repo   string `json:"repo"`
		Branch string `json:"branch"`
	}{
		Prompt: prompt,
		User:   gitCmd(cwd, "config", "user.name"),
		Email:  getClaudeEmail(),
		Repo:   filepath.Base(gitCmd(cwd, "rev-parse", "--show-toplevel")),
		Branch: gitCmd(cwd, "branch", "--show-current"),
	}
	if _, err := postJSON(getServerURL()+"/Hooks/LogPrompt", token, body); err != nil {
		logf("WARN", "log-prompt: POST failed: %v", err)
	}
}

// =============================================================================
// Entry point
// =============================================================================

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
