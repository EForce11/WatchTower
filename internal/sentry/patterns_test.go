package sentry

import (
	"testing"
)

// ── helpers ──────────────────────────────────────────────────────────────────

func firstMatchName(matches []PatternMatch) string {
	if len(matches) == 0 {
		return ""
	}
	return matches[0].PatternName
}

func hasPattern(matches []PatternMatch, name string) bool {
	for _, m := range matches {
		if m.PatternName == name {
			return true
		}
	}
	return false
}

// ── SSH ───────────────────────────────────────────────────────────────────────

func TestPatternMatcher_SSH_FailedPassword(t *testing.T) {
	pm := NewPatternMatcher()

	line := "Failed password for root from 192.168.1.100 port 22 ssh2"
	matches := pm.Match(line)

	if len(matches) == 0 {
		t.Fatal("Expected SSH pattern match, got none")
	}
	if !hasPattern(matches, "SSH_FAILED_PASSWORD") {
		t.Errorf("Expected SSH_FAILED_PASSWORD in matches, got %v", firstMatchName(matches))
	}
	// Verify the IP capture group is present
	for _, m := range matches {
		if m.PatternName == "SSH_FAILED_PASSWORD" {
			if len(m.Matches) < 2 || m.Matches[1] == "" {
				t.Error("Expected IP address capture group to be populated")
			}
			break
		}
	}
}

func TestPatternMatcher_SSH_InvalidUser(t *testing.T) {
	pm := NewPatternMatcher()

	line := "Invalid user admin from 10.0.0.5 port 4444"
	matches := pm.Match(line)

	if !hasPattern(matches, "SSH_INVALID_USER") {
		t.Errorf("Expected SSH_INVALID_USER, got matches: %v", matches)
	}
}

// ── SQL Injection ─────────────────────────────────────────────────────────────

func TestPatternMatcher_SQLi(t *testing.T) {
	pm := NewPatternMatcher()

	tests := []struct {
		line    string
		pattern string
	}{
		{"SELECT * FROM users WHERE id=1 UNION SELECT password FROM users", "SQLI_UNION"},
		{"admin'--", "SQLI_COMMENT"},
		{"admin' OR '1'='1", "SQLI_OR_TRUE"},
	}

	for _, tt := range tests {
		matches := pm.Match(tt.line)
		if len(matches) == 0 {
			t.Errorf("No match for line: %s", tt.line)
			continue
		}
		if !hasPattern(matches, tt.pattern) {
			t.Errorf("Expected %s for line %q; got %s", tt.pattern, tt.line, firstMatchName(matches))
		}
	}
}

// ── XSS ──────────────────────────────────────────────────────────────────────

func TestPatternMatcher_XSS(t *testing.T) {
	pm := NewPatternMatcher()

	tests := []struct {
		line    string
		pattern string
	}{
		{`GET /?q=<script>alert('XSS')</script> HTTP/1.1`, "XSS_SCRIPT_TAG"},
		{`GET /?q=<img src=x onerror=alert(1)> HTTP/1.1`, "XSS_EVENT_HANDLER"},
		{`GET /?url=javascript:alert(1) HTTP/1.1`, "XSS_JAVASCRIPT_URI"},
	}

	for _, tt := range tests {
		matches := pm.Match(tt.line)
		if len(matches) == 0 {
			t.Errorf("No match for line: %s", tt.line)
			continue
		}
		if !hasPattern(matches, tt.pattern) {
			t.Errorf("Expected %s for %q; got %s", tt.pattern, tt.line, firstMatchName(matches))
		}
	}
}

// ── Path Traversal ────────────────────────────────────────────────────────────

func TestPatternMatcher_PathTraversal(t *testing.T) {
	pm := NewPatternMatcher()

	tests := []struct {
		line    string
		pattern string
	}{
		{"GET ../../etc/passwd HTTP/1.1", "PATH_TRAVERSAL"},
		{"GET /%2e%2e%2fetc%2fpasswd HTTP/1.1", "PATH_TRAVERSAL_ENCODED"},
	}

	for _, tt := range tests {
		matches := pm.Match(tt.line)
		if len(matches) == 0 {
			t.Errorf("Expected path traversal match for: %s", tt.line)
			continue
		}
		if !hasPattern(matches, tt.pattern) {
			t.Errorf("Expected %s for %q; got %s", tt.pattern, tt.line, firstMatchName(matches))
		}
	}
}

// ── Port Scanning ─────────────────────────────────────────────────────────────

func TestPatternMatcher_PortScan(t *testing.T) {
	pm := NewPatternMatcher()

	line := "KERNEL: SYN packet eth0 sport=12345 dport=80"
	matches := pm.Match(line)

	if !hasPattern(matches, "PORT_SCAN") {
		t.Errorf("Expected PORT_SCAN match, got: %v", matches)
	}
}

// ── Command Injection ─────────────────────────────────────────────────────────

func TestPatternMatcher_CommandInjection(t *testing.T) {
	pm := NewPatternMatcher()

	tests := []struct {
		line    string
		pattern string
	}{
		{"GET /ping?host=127.0.0.1;whoami HTTP/1.1", "COMMAND_INJECTION"},
		{"GET /exec?cmd=$(whoami) HTTP/1.1", "COMMAND_INJECTION_SUBSHELL"},
	}

	for _, tt := range tests {
		matches := pm.Match(tt.line)
		if len(matches) == 0 {
			t.Errorf("No match for line: %s", tt.line)
			continue
		}
		if !hasPattern(matches, tt.pattern) {
			t.Errorf("Expected %s for %q; got %s", tt.pattern, tt.line, firstMatchName(matches))
		}
	}
}

// ── Malicious File Upload ─────────────────────────────────────────────────────

func TestPatternMatcher_MaliciousFileUpload(t *testing.T) {
	pm := NewPatternMatcher()

	tests := []struct {
		line string
	}{
		{`POST /upload/shell.php HTTP/1.1`},
		{`POST /upload/backdoor.jsp HTTP/1.1`},
		{`POST /upload/evil.sh HTTP/1.1`},
	}

	for _, tt := range tests {
		matches := pm.Match(tt.line)
		if !hasPattern(matches, "MALICIOUS_FILE_UPLOAD") {
			t.Errorf("Expected MALICIOUS_FILE_UPLOAD for: %s (got %v)", tt.line, matches)
		}
	}
}

// ── No match ─────────────────────────────────────────────────────────────────

func TestPatternMatcher_NoMatch(t *testing.T) {
	pm := NewPatternMatcher()

	benign := []string{
		"Normal log entry: user john logged in successfully",
		"INFO: server started on port 8080",
		"GET /healthz HTTP/1.1 200 0",
	}

	for _, line := range benign {
		matches := pm.Match(line)
		if len(matches) != 0 {
			t.Errorf("Expected no matches for %q, got: %v", line, matches)
		}
	}
}

// ── Pattern count ─────────────────────────────────────────────────────────────

func TestPatternMatcher_Count(t *testing.T) {
	pm := NewPatternMatcher()

	const minPatterns = 10
	if len(pm.patterns) < minPatterns {
		t.Errorf("Expected at least %d patterns, got %d", minPatterns, len(pm.patterns))
	}
}

// ── Severity bounds ───────────────────────────────────────────────────────────

func TestPatternMatcher_SeverityBounds(t *testing.T) {
	pm := NewPatternMatcher()

	for _, p := range pm.patterns {
		if p.Severity < 1 || p.Severity > 4 {
			t.Errorf("Pattern %s has out-of-range severity %d (expected 1-4)", p.Name, p.Severity)
		}
	}
}

// ── Edge Cases ────────────────────────────────────────────────────────────────

func TestPatternMatcher_EdgeCases(t *testing.T) {
	pm := NewPatternMatcher()

	// Empty string
	if len(pm.Match("")) != 0 {
		t.Error("Expected no matches for empty string")
	}

	// Very long string
	longStr := "A"
	for i := 0; i < 10000; i++ {
		longStr += "A"
	}
	if len(pm.Match(longStr)) != 0 {
		t.Error("Expected no matches for very long benign string")
	}

	// Unicode / Binary
	binaryStr := string([]byte{0x00, 0xFF, 0xFE, 0x01, 0x02})
	if len(pm.Match(binaryStr)) != 0 {
		t.Error("Expected no matches for binary string")
	}
}

// ── Multiple Matches ──────────────────────────────────────────────────────────

func TestPatternMatcher_MultipleMatches(t *testing.T) {
	pm := NewPatternMatcher()

	line := "GET /?q=' OR '1'='1 <script>alert(1)</script> HTTP/1.1"
	matches := pm.Match(line)

	if len(matches) != 2 {
		t.Errorf("Expected 2 matches (SQLi and XSS), got %d", len(matches))
	}

	hasSQLi := false
	hasXSS := false
	for _, m := range matches {
		if m.PatternName == "SQLI_OR_TRUE" {
			hasSQLi = true
		}
		if m.PatternName == "XSS_SCRIPT_TAG" {
			hasXSS = true
		}
	}

	if !hasSQLi || !hasXSS {
		t.Errorf("Expected SQLI_OR_TRUE and XSS_SCRIPT_TAG matches, got: %v", matches)
	}
}

// ── Missing Specific Patterns ─────────────────────────────────────────────────

func TestPatternMatcher_SSH_RootLogin(t *testing.T) {
	pm := NewPatternMatcher()

	line := "Failed password for root from 192.168.1.100 port 22 ssh2"
	matches := pm.Match(line)

	if !hasPattern(matches, "SSH_ROOT_LOGIN") {
		t.Errorf("Expected SSH_ROOT_LOGIN match, got %v", matches)
	}
}

func TestPatternMatcher_CaptureGroups(t *testing.T) {
	pm := NewPatternMatcher()

	line := "KERNEL: SYN packet eth0 sport=12345 dport=80"
	matches := pm.Match(line)

	var scanMatch *PatternMatch
	for i, m := range matches {
		if m.PatternName == "PORT_SCAN" {
			scanMatch = &matches[i]
			break
		}
	}

	if scanMatch == nil {
		t.Fatalf("Expected PORT_SCAN match")
	}

	if len(scanMatch.Matches) < 3 {
		t.Fatalf("Expected at least 3 capture groups (full match, start port, dest port), got %d", len(scanMatch.Matches))
	}

	if scanMatch.Matches[1] != "12345" || scanMatch.Matches[2] != "80" {
		t.Errorf("Expected ports 12345 and 80, got %s and %s", scanMatch.Matches[1], scanMatch.Matches[2])
	}
}

// ── Negative Tests (False Positives) ──────────────────────────────────────────

func TestPatternMatcher_FalsePositives(t *testing.T) {
	pm := NewPatternMatcher()

	tests := []string{
		"Please select your preferred option from the menu", // SQLI_UNION false positive check
		"The union of these two sets is empty",              // SQLI_UNION false positive check
		"This is a typescript file",                         // XSS_SCRIPT_TAG false positive check
		"Uploading a valid image.png",                       // MALICIOUS_FILE_UPLOAD false positive
		"Document available at /users/admin/report.pdf",     // MALICIOUS_FILE_UPLOAD false positive
	}

	for _, tt := range tests {
		matches := pm.Match(tt)
		if len(matches) > 0 {
			t.Errorf("Expected no matches for innocent line: %q, but got %v", tt, matches)
		}
	}
}
