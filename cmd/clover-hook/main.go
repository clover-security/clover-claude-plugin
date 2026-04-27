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
	"strconv"
	"strings"
	"time"
)

// skipMarkerRegex matches [SKIP:N — reason] anywhere in text and captures the
// integer id (group 1) and the free-form reason (group 2, optional).
var skipMarkerRegex = regexp.MustCompile(`\[SKIP:\s*(\d+)(?:\s*(?:[—\-–]|--)\s*([^\]]*?))?\s*\]`)

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
	ToolInput toolInput `json:"tool_input"`
}

type toolInput struct {
	Plan         string `json:"plan"`
	PlanFilePath string `json:"planFilePath"` // may be absent; we fall back to findPlanFile
}

// clientRequirement mirrors the server's HookClientRequirement — a requirement
// carried alongside its stable PlanSessionRequirementId (the integer the user
// writes as [SKIP:N] in the skips file).
type clientRequirement struct {
	PlanSessionRequirementID int    `json:"planSessionRequirementId"`
	Requirement              string `json:"requirement"`
}

// skipRequirement mirrors the server's HookSkipRequirement — a typed skip
// directive pairing a requirement's stable PlanSessionRequirementId with an
// optional free-form reason.
type skipRequirement struct {
	PlanSessionRequirementID int    `json:"planSessionRequirementId"`
	Reason                   string `json:"reason,omitempty"`
}

// sessionState is round-tripped verbatim between plugin invocations and the server.
// LastPlan / LastDenyReason are plugin-local (server ignores them).
type sessionState struct {
	CodingPlanId   string              `json:"codingPlanId,omitempty"`
	LastDenyReason string              `json:"lastDenyReason,omitempty"`
	LastPlan       string              `json:"lastPlan,omitempty"`
	Must           []clientRequirement `json:"must"`
	ReviewCount    int                 `json:"reviewCount"`
}

// baseRequest carries the session id shared by every /Hooks/* endpoint.
// Go embeds this anonymously so the field flattens into the JSON body.
// Mirrors the server's HooksControllerRequestBase.
type baseRequest struct {
	SessionID string `json:"sessionId"`
}

// planRequest is baseRequest + the plan text, shared by /Hooks/ReviewPlan and
// /Hooks/JudgePlan. Mirrors the server's HooksControllerPlanRequestBase.
type planRequest struct {
	baseRequest
	Plan string `json:"plan"`
}

// reviewRequest starts a fresh analysis — sent when no prior session state exists.
type reviewRequest struct {
	planRequest
	Branch     string `json:"branch,omitempty"`
	Email      string `json:"email,omitempty"`
	PlanFile   string `json:"planFile,omitempty"`
	Repository string `json:"repository,omitempty"`
}

// judgeRequest re-evaluates an existing plan, applying any skipped requirements
// the user collected since the last round.
type judgeRequest struct {
	planRequest
	CodingPlanID     string            `json:"codingPlanId"`
	SkipRequirements []skipRequirement `json:"skipRequirements,omitempty"`
}

type pollRequest struct {
	baseRequest
	TaskID string `json:"taskId"`
}

// logPromptRequest posts a user prompt submission for audit. Shares the git
// context fields with reviewRequest.
type logPromptRequest struct {
	baseRequest
	Branch     string `json:"branch,omitempty"`
	Email      string `json:"email,omitempty"`
	Prompt     string `json:"prompt"`
	Repository string `json:"repository,omitempty"`
}

type reviewResponse struct {
	Approved     bool          `json:"approved"`
	Reason       string        `json:"reason"`
	SessionState *sessionState `json:"sessionState,omitempty"`
	TaskID       string        `json:"taskId"`
}

// reviewResponseEnvelope mirrors the server's controller wrapper:
// every /Hooks/* response comes back as { "result": HookReviewResultDto }.
// Without this envelope the Go decode silently returns zero values for
// every field — taskId in particular ends up "", which means the polling
// loop never starts and the plugin falls through to a no-reason deny.
type reviewResponseEnvelope struct {
	Result reviewResponse `json:"result"`
}

func decodeReviewResponse(body []byte) (reviewResponse, error) {
	var envelope reviewResponseEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		return reviewResponse{}, err
	}
	return envelope.Result, nil
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

// getClaudeEmail reads the account email from ~/.claude.json (shared by the
// Claude Code CLI and Desktop app). `claude auth status --json` no longer
// exposes the email field as of CLI 2.x.
func getClaudeEmail() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	data, err := os.ReadFile(filepath.Join(home, ".claude.json"))
	if err != nil {
		return ""
	}
	var r struct {
		OauthAccount struct{ EmailAddress string `json:"emailAddress"` } `json:"oauthAccount"`
	}
	json.Unmarshal(data, &r)
	return r.OauthAccount.EmailAddress
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

// resolveRepositoryName returns the basename of the git toplevel (e.g. "leaf"
// for /Users/x/Code/leaf), or "" when cwd isn't inside a git repo. Empty
// triggers the `omitempty` JSON tag on the wire field, which is what the
// server expects when it can't be determined — sending the literal "unknown"
// would falsely match the default-application fallback path.
func resolveRepositoryName(cwd string) string {
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	cmd.Dir = cwd
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	topLevel := strings.TrimSpace(string(out))
	if topLevel == "" {
		return ""
	}
	return filepath.Base(topLevel)
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

// sessionIdSidecarPath stores the sessionId next to the plan file so it
// survives Claude restarts (which mint a new ephemeral sessionId per process).
// When this file exists next to a plan, we treat it as the canonical sessionId
// for that plan and ignore the one Claude hands us.
func sessionIdSidecarPath(planFile, sessionId string) string {
	return sidecarPath(planFile, sessionId, ".clover-session.json")
}

type sessionIdSidecar struct {
	SessionID string `json:"sessionId"`
}

func readSessionIdSidecar(planFile string) string {
	if planFile == "" {
		return ""
	}
	data, err := os.ReadFile(sessionIdSidecarPath(planFile, ""))
	if err != nil {
		return ""
	}
	var s sessionIdSidecar
	if err := json.Unmarshal(data, &s); err != nil {
		logf("WARN", "session_sidecar unmarshal failed err=%v", err)
		return ""
	}
	return s.SessionID
}

func writeSessionIdSidecar(planFile, sessionId string) {
	if planFile == "" || sessionId == "" {
		return
	}
	path := sessionIdSidecarPath(planFile, sessionId)
	data, _ := json.Marshal(sessionIdSidecar{SessionID: sessionId})
	if err := os.WriteFile(path, data, 0600); err != nil {
		logf("WARN", "session_sidecar write failed path=%s err=%v", path, err)
	}
}

func writeRequirementsFile(planFile, sessionId, reason string) {
	if err := os.WriteFile(requirementsFilePath(planFile, sessionId), []byte(reason+"\n"), 0600); err != nil {
		logf("WARN", "requirements write failed err=%v", err)
	}
}

func clearSidecarFiles(planFile, sessionId string) {
	os.Remove(requirementsFilePath(planFile, sessionId))
	os.Remove(skipsFilePath(planFile, sessionId))
	if planFile != "" {
		os.Remove(sessionIdSidecarPath(planFile, sessionId))
	}
}

// removeSkipRequirementsFile drops just the skips sidecar, keeping the
// requirements file and the session pin in place. Called after the server
// has confirmed it consumed the skip requirements — the entries are now
// persisted as Skipped rows in the DB and re-sending them next round would
// be wasteful and confusing if the user later wants to "unskip" something.
func removeSkipRequirementsFile(planFile, sessionId string) {
	path := skipsFilePath(planFile, sessionId)
	err := os.Remove(path)
	if err == nil {
		logf("DEBUG", "skip_file removed after server ack path=%s", path)
		return
	}
	if !os.IsNotExist(err) {
		logf("WARN", "skip_file remove failed path=%s err=%v", path, err)
	}
}

// parseSkipRequirementsFromSidecar reads skip decisions from the dedicated
// skips file and returns them as typed skipRequirement objects. The agent
// writes [SKIP:N — reason] lines to {plan-stem}.clover-skips.md; we parse the
// index and (optional) reason here so the server never has to do regex on user
// input.
func parseSkipRequirementsFromSidecar(planFile, sessionId string) []skipRequirement {
	data, err := os.ReadFile(skipsFilePath(planFile, sessionId))
	if err != nil {
		return nil
	}

	matches := skipMarkerRegex.FindAllStringSubmatch(string(data), -1)
	if len(matches) == 0 {
		return nil
	}

	seen := make(map[int]bool, len(matches))
	skipRequirements := make([]skipRequirement, 0, len(matches))
	for _, match := range matches {
		id, err := strconv.Atoi(match[1])
		if err != nil {
			continue
		}
		if seen[id] {
			continue
		}
		seen[id] = true

		reason := ""
		if len(match) > 2 {
			reason = strings.TrimSpace(match[2])
		}
		skipRequirements = append(skipRequirements, skipRequirement{PlanSessionRequirementID: id, Reason: reason})
	}
	return skipRequirements
}

// normalizePlanContent collapses whitespace differences that defeat exact
// matching between Claude's in-memory plan and the on-disk file (line ending
// variations, trailing newlines, leading/trailing space).
func normalizePlanContent(content string) string {
	normalized := strings.ReplaceAll(content, "\r\n", "\n")
	return strings.TrimSpace(normalized)
}

// firstNonEmptyLine returns the first non-blank line of the input, trimmed.
// Used as a coarse plan-identity check: most plans start with a "# Title"
// line that survives in-place edits to the body.
func firstNonEmptyLine(content string) string {
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}

// findPlanFile discovers the plan's on-disk path by scanning ~/.claude/plans/.
// Strategy, in order:
//  1. Exact normalized content match (whitespace-tolerant).
//  2. First-line (plan title) match — survives mid-plan edits.
//  3. Most-recently-modified .md within 5 minutes — survives slow user actions.
// Returns "" only when every strategy fails (no recent .md files at all).
func findPlanFile(plan string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	plansDir := filepath.Join(home, ".claude", "plans")
	entries, err := os.ReadDir(plansDir)
	if err != nil {
		logf("WARN", "plan_file plans_dir_unreadable path=%s err=%v", plansDir, err)
		return ""
	}

	normPlan := normalizePlanContent(plan)
	planFirstLine := firstNonEmptyLine(normPlan)

	var titleMatchPath string
	var latestInfo os.FileInfo
	var latestPath string

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		path := filepath.Join(plansDir, e.Name())
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			continue
		}
		normFile := normalizePlanContent(string(data))

		// Strategy 1: exact normalized match.
		if normFile == normPlan {
			logf("DEBUG", "plan_file content_match path=%s", path)
			return path
		}

		// Strategy 2: title (first non-empty line) match — keep as candidate.
		if planFirstLine != "" && titleMatchPath == "" && firstNonEmptyLine(normFile) == planFirstLine {
			titleMatchPath = path
		}

		// Strategy 3: track most-recent .md for the mtime fallback.
		if info, infoErr := e.Info(); infoErr == nil {
			if latestInfo == nil || info.ModTime().After(latestInfo.ModTime()) {
				latestInfo, latestPath = info, path
			}
		}
	}

	if titleMatchPath != "" {
		logf("DEBUG", "plan_file title_match path=%s", titleMatchPath)
		return titleMatchPath
	}

	// Five-minute window covers slow user actions (re-reading the plan, browsing
	// dependencies) without picking up a stale plan from a prior session.
	if latestInfo != nil && time.Since(latestInfo.ModTime()) < 5*time.Minute {
		logf("DEBUG", "plan_file mtime_fallback path=%s age=%s", latestPath, time.Since(latestInfo.ModTime()))
		return latestPath
	}

	logf("WARN", "plan_file not_found scanned=%s", plansDir)
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

	// If a sessionId sidecar exists next to the plan, it wins over the ephemeral
	// sessionId Claude provides — so the same plan file resumes the same review
	// session across Claude restarts.
	sessionId := hook.SessionID
	if persistedSessionId := readSessionIdSidecar(planFilePath); persistedSessionId != "" {
		if persistedSessionId != sessionId {
			logf("INFO", "session_sidecar override claude_session=%s persisted_session=%s plan_file=%q",
				sessionId, persistedSessionId, planFilePath)
		}
		sessionId = persistedSessionId
	}

	logf("INFO", "session=%s plan_chars=%d plan_file=%q cwd=%q",
		sessionId, len(plan), planFilePath, hook.CWD)

	if plan == "" {
		logf("INFO", "action=allow reason=empty_plan session=%s", sessionId)
		fmt.Println(allowJSON())
		return
	}

	token, err := getAccessToken()
	if err != nil {
		logf("ERROR", "action=allow reason=auth_failed session=%s err=%v", sessionId, err)
		fmt.Println(allowJSON())
		return
	}

	cwd := hook.CWD
	if cwd == "" {
		cwd = "."
	}

	persisted := loadSessionState(sessionId)

	start := time.Now()
	deadline := start.Add(3 * time.Minute)

	// Two endpoints, picked based on whether we already have a server-side plan:
	//   - No persisted state  → /Hooks/ReviewPlan  (starts analysis, returns taskId)
	//   - Persisted state     → /Hooks/JudgePlan   (re-evaluates with skips)
	var respBody []byte
	var postErr error
	// Track whether the current request actually carried skip requirements to
	// the server. If it did and the server acks, we drop the local sidecar
	// below so the user's `[SKIP:N]` markers are not re-sent on the next round
	// (the server already persisted them as Skipped rows in the DB).
	sentSkipRequirements := false
	if persisted != nil && persisted.CodingPlanId != "" {
		skipRequirements := parseSkipRequirementsFromSidecar(planFilePath, sessionId)

		// Short-circuit only when nothing has changed — same plan, no new skips.
		// If the user added a [SKIP:N] marker we still need to call the server
		// so it can re-evaluate with the new skip list.
		if persisted.LastPlan == plan && persisted.LastDenyReason != "" && len(skipRequirements) == 0 {
			logf("INFO", "short_circuit plan_unchanged review_count=%d session=%s", persisted.ReviewCount, sessionId)
			fmt.Println(denyJSON(persisted.LastDenyReason))
			return
		}
		logf("INFO", "flow=judge review_count=%d must=%d skip_requirements=%d session=%s",
			persisted.ReviewCount, len(persisted.Must), len(skipRequirements), sessionId)

		sentSkipRequirements = len(skipRequirements) > 0

		respBody, postErr = postJSON(getServerURL()+"/Hooks/JudgePlan", token, judgeRequest{
			planRequest:      planRequest{baseRequest: baseRequest{SessionID: sessionId}, Plan: plan},
			CodingPlanID:     persisted.CodingPlanId,
			SkipRequirements: skipRequirements,
		})
	} else {
		logf("INFO", "flow=start session=%s", sessionId)

		respBody, postErr = postJSON(getServerURL()+"/Hooks/ReviewPlan", token, reviewRequest{
			planRequest: planRequest{baseRequest: baseRequest{SessionID: sessionId}, Plan: plan},
			Branch:      gitCmd(cwd, "branch", "--show-current"),
			Email:       getClaudeEmail(),
			PlanFile:    planFilePath,
			Repository:  resolveRepositoryName(cwd),
		})
	}
	if postErr != nil {
		logf("ERROR", "action=allow reason=server_unreachable session=%s err=%v", sessionId, postErr)
		fmt.Println(allowJSON())
		return
	}

	resp, err := decodeReviewResponse(respBody)
	if err != nil {
		logf("ERROR", "action=allow reason=bad_response session=%s err=%v", sessionId, err)
		fmt.Println(allowJSON())
		return
	}

	// Server acknowledged the request — the skip requirements we sent are now
	// persisted server-side as Skipped rows. Drop the local sidecar so the next
	// hook round doesn't re-submit the same entries (the user can still write
	// new [SKIP:N] markers; only the consumed ones go away).
	if sentSkipRequirements {
		removeSkipRequirementsFile(planFilePath, sessionId)
	}

	// As soon as the server has acknowledged this plan (with a taskId or final
	// verdict), pin the sessionId to the plan file so a future Claude restart
	// reuses the same server-side CodingPlan.
	writeSessionIdSidecar(planFilePath, sessionId)

	for pendingCount := 0; resp.TaskID != ""; pendingCount++ {
		if time.Now().After(deadline) {
			logf("WARN", "action=allow reason=poll_timeout polls=%d session=%s", pendingCount, sessionId)
			fmt.Println(allowJSON())
			return
		}
		logf("INFO", "poll task=%s count=%d elapsed=%.1fs session=%s",
			resp.TaskID, pendingCount, time.Since(start).Seconds(), sessionId)
		time.Sleep(3 * time.Second)

		respBody, err = postJSON(getServerURL()+"/Hooks/PollReview", token, pollRequest{
			baseRequest: baseRequest{SessionID: sessionId},
			TaskID:      resp.TaskID,
		})
		if err != nil {
			logf("ERROR", "action=allow reason=poll_unreachable session=%s err=%v", sessionId, err)
			fmt.Println(allowJSON())
			return
		}
		resp, err = decodeReviewResponse(respBody)
		if err != nil {
			logf("ERROR", "action=allow reason=bad_poll_response session=%s err=%v", sessionId, err)
			fmt.Println(allowJSON())
			return
		}
	}

	mustCount := 0
	if resp.SessionState != nil {
		mustCount = len(resp.SessionState.Must)
	}
	logf("INFO", "verdict approved=%t must=%d elapsed=%.1fs session=%s",
		resp.Approved, mustCount, time.Since(start).Seconds(), sessionId)

	if resp.Approved {
		clearSessionState(sessionId)
		clearSidecarFiles(planFilePath, sessionId)
		logf("INFO", "action=allow reason=approved session=%s", sessionId)
		fmt.Println(allowJSON())
		return
	}

	if resp.SessionState != nil {
		// The server is authoritative for Must — it already reflects skips and
		// mitigations applied this round. Persist what the server sent plus our
		// local-only cache fields.
		stateToSave := resp.SessionState
		stateToSave.LastPlan = plan
		stateToSave.LastDenyReason = resp.Reason
		saveSessionState(sessionId, stateToSave)
	} else {
		logf("WARN", "deny had no sessionState session=%s", sessionId)
	}
	writeRequirementsFile(planFilePath, sessionId, resp.Reason)
	logf("INFO", "action=deny reason_chars=%d elapsed=%.1fs session=%s",
		len(resp.Reason), time.Since(start).Seconds(), sessionId)
	fmt.Println(denyJSON(resp.Reason))
}

// logPromptInput is the shape Claude passes to the UserPromptSubmit hook on
// stdin. We only extract the fields we forward to the server.
type logPromptInput struct {
	CWD       string `json:"cwd"`
	Prompt    string `json:"prompt"`
	SessionID string `json:"session_id"`
}

func handleLogPrompt(input []byte) {
	token, err := getAccessToken()
	if err != nil {
		logf("WARN", "log-prompt: auth failed: %v", err)
		return
	}
	var hook logPromptInput
	if err := json.Unmarshal(input, &hook); err != nil {
		logf("WARN", "log-prompt: parse error: %v", err)
		return
	}
	cwd := hook.CWD
	if cwd == "" {
		cwd = "."
	}
	body := logPromptRequest{
		baseRequest: baseRequest{SessionID: hook.SessionID},
		Branch:      gitCmd(cwd, "branch", "--show-current"),
		Email:       getClaudeEmail(),
		Prompt:      hook.Prompt,
		Repository:  resolveRepositoryName(cwd),
	}
	if _, err := postJSON(getServerURL()+"/Hooks/LogPrompt", token, body); err != nil {
		logf("WARN", "log-prompt: POST failed session=%s err=%v", hook.SessionID, err)
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
