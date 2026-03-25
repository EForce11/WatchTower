package sentry

import (
	"regexp"
)

// Pattern represents a security detection pattern.
type Pattern struct {
	Name        string
	Regex       *regexp.Regexp
	Severity    int // 1=low, 2=medium, 3=high, 4=critical
	Description string
}

// PatternMatch represents a detected pattern in a log line.
type PatternMatch struct {
	PatternName string
	Severity    int
	Description string
	Line        string
	Matches     []string // Regex capture groups
}

// PatternMatcher holds all compiled security detection patterns.
type PatternMatcher struct {
	patterns []Pattern
}

// NewPatternMatcher creates a PatternMatcher pre-loaded with default security patterns.
func NewPatternMatcher() *PatternMatcher {
	return &PatternMatcher{
		patterns: []Pattern{
			// ── SSH ──────────────────────────────────────────────────────────────
			{
				Name:        "SSH_FAILED_PASSWORD",
				Regex:       regexp.MustCompile(`Failed password for .* from ([\d\.]+)`),
				Severity:    2,
				Description: "SSH failed login attempt",
			},
			{
				Name:        "SSH_INVALID_USER",
				Regex:       regexp.MustCompile(`Invalid user .* from ([\d\.]+)`),
				Severity:    2,
				Description: "SSH login attempt with invalid user",
			},
			{
				Name:        "SSH_ROOT_LOGIN",
				Regex:       regexp.MustCompile(`Failed password for root from ([\d\.]+)`),
				Severity:    3,
				Description: "SSH root login attempt",
			},

			// ── SQL Injection ─────────────────────────────────────────────────
			{
				Name:        "SQLI_UNION",
				Regex:       regexp.MustCompile(`(?i)\bunion\s+(all\s+)?select\b`),
				Severity:    4,
				Description: "SQL injection attempt (UNION/SELECT)",
			},
			{
				Name:        "SQLI_COMMENT",
				Regex:       regexp.MustCompile(`(--|#|/\*|\*/)`),
				Severity:    3,
				Description: "SQL injection attempt (comment syntax)",
			},
			{
				Name:        "SQLI_OR_TRUE",
				Regex:       regexp.MustCompile(`(?i)'\s*(or|and)\s+'?\d+'?\s*=\s*'?\d+`),
				Severity:    4,
				Description: "SQL injection attempt (OR/AND tautology)",
			},

			// ── XSS ───────────────────────────────────────────────────────────
			{
				Name:        "XSS_SCRIPT_TAG",
				Regex:       regexp.MustCompile(`(?i)<script[^>]*>.*`),
				Severity:    4,
				Description: "XSS attempt (script tag)",
			},
			{
				Name:        "XSS_EVENT_HANDLER",
				Regex:       regexp.MustCompile(`(?i)on(load|error|click|mouseover|focus|blur)=`),
				Severity:    3,
				Description: "XSS attempt (event handler)",
			},
			{
				Name:        "XSS_JAVASCRIPT_URI",
				Regex:       regexp.MustCompile(`(?i)javascript\s*:`),
				Severity:    3,
				Description: "XSS attempt (javascript: URI)",
			},

			// ── Path Traversal ────────────────────────────────────────────────
			{
				Name:        "PATH_TRAVERSAL",
				Regex:       regexp.MustCompile(`\.\./|\.\.\\`),
				Severity:    3,
				Description: "Directory traversal attempt",
			},
			{
				Name:        "PATH_TRAVERSAL_ENCODED",
				Regex:       regexp.MustCompile(`(%2e%2e%2f|%2e%2e/|\.\.%2f)`),
				Severity:    3,
				Description: "URL-encoded directory traversal attempt",
			},

			// ── Port Scanning ─────────────────────────────────────────────────
			{
				Name:        "PORT_SCAN",
				Regex:       regexp.MustCompile(`SYN.*sport=(\d+).*dport=(\d+)`),
				Severity:    2,
				Description: "Potential port scanning activity",
			},

			// ── Command Injection ─────────────────────────────────────────────
			{
				Name:        "COMMAND_INJECTION",
				Regex:       regexp.MustCompile("(;|\\||&|`).*?(\\bcat\\b|\\bls\\b|\\bwhoami\\b|\\bpwd\\b|\\bid\\b)"),
				Severity:    4,
				Description: "Command injection attempt",
			},
			{
				Name:        "COMMAND_INJECTION_SUBSHELL",
				Regex:       regexp.MustCompile(`\$\(.*\b(cat|ls|whoami|id|uname)\b.*\)`),
				Severity:    4,
				Description: "Command injection via subshell substitution",
			},

			// ── Malicious File Upload ─────────────────────────────────────────
			{
				Name:        "MALICIOUS_FILE_UPLOAD",
				Regex:       regexp.MustCompile(`(?i)\.(php|jsp|asp|aspx|sh|bat|exe|ps1|py)(\?|\s|$)`),
				Severity:    3,
				Description: "Potentially malicious file upload",
			},
		},
	}
}

// Match checks a log line against all registered patterns and returns every match found.
func (pm *PatternMatcher) Match(line string) []PatternMatch {
	var matches []PatternMatch

	for _, pattern := range pm.patterns {
		if pattern.Regex.MatchString(line) {
			matches = append(matches, PatternMatch{
				PatternName: pattern.Name,
				Severity:    pattern.Severity,
				Description: pattern.Description,
				Line:        line,
				Matches:     pattern.Regex.FindStringSubmatch(line),
			})
		}
	}

	return matches
}
