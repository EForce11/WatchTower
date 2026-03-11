# GitHub Codex - WatchTower XDR Security Review Configuration

**Purpose:** Automated security and quality review for all PRs and commits  
**Scope:** Focus on security-critical components (patterns, database, firewall, auth)  
**Integration:** GitHub Copilot / Codex with PR review capabilities

---

## 🎯 Review Objectives

### Primary Goals:
1. **Prevent security vulnerabilities** before merge
2. **Catch bugs** in critical paths
3. **Ensure test coverage** >80% for critical components
4. **Validate input handling** in all external-facing code

### Secondary Goals:
- Code quality improvements
- Performance recommendations
- Best practice adherence

---

## 🔍 Auto-Review Triggers

### When to Review (File Patterns)

**CRITICAL - Always Review:**
```
internal/sentry/patterns.go          # Security patterns
internal/core/storage.go             # Database layer
internal/turret/firewall.go          # Firewall rules
internal/interceptor/waf.go          # WAF engine
internal/*/auth*.go                  # Authentication
pkg/protocol/*.proto                 # API definitions
```

**IMPORTANT - Review if Changed:**
```
cmd/wt-*/main.go                     # Entry points
internal/core/receiver.go            # Event processing
internal/sentry/logwatcher.go        # Input handling
test/integration/*_test.go           # Integration tests
```

**STANDARD - Quick Review:**
```
internal/*/metrics.go                # Monitoring
cmd/wt-cli/*                         # CLI tools
```

---

## 🛡️ Security Review Checklist

### For Every PR Touching Critical Files:

#### 1. Input Validation
```
Check:
- [ ] All external input validated
- [ ] Length limits enforced
- [ ] Type checking present
- [ ] Null byte filtering
- [ ] Unicode normalization

Red Flags:
❌ Direct string concatenation in SQL
❌ Unvalidated user input in exec()
❌ No length limits on strings
❌ Missing error handling
❌ Hardcoded credentials
```

#### 2. SQL Injection Prevention
```
CRITICAL if files match: **/storage.go, **/db.go, **/database.go

Check:
- [ ] Parameterized queries ONLY ($1, $2, ...)
- [ ] No fmt.Sprintf() in SQL
- [ ] No string concatenation in queries
- [ ] SQL injection tests present

Example GOOD code:
✅ query := `INSERT INTO events VALUES ($1, $2, $3)`
✅ db.Exec(query, event.AgentId, event.Type, event.Message)

Example BAD code:
❌ query := fmt.Sprintf("INSERT INTO events VALUES ('%s')", agentId)
❌ query := "INSERT INTO events VALUES ('" + agentId + "')"

Auto-REJECT if:
- Any SQL query uses string concatenation
- Missing test for SQL injection
```

#### 3. Regular Expression Security
```
CRITICAL if files match: **/patterns.go

Check:
- [ ] ReDoS prevention (catastrophic backtracking)
- [ ] Regex timeout configured
- [ ] Input length limits
- [ ] Performance tests present

Test each pattern with:
- strings.Repeat("a", 10000) + "X"
- Nested quantifiers: (a+)+
- Alternation explosion: (a|ab)*

Auto-COMMENT if:
- Pattern contains nested quantifiers
- Pattern contains .* or .+
- No timeout on regex matching
- Missing performance benchmarks
```

#### 4. Command Injection
```
CRITICAL if code contains: exec.Command, os/exec

Check:
- [ ] No user input in command
- [ ] Whitelist of allowed commands
- [ ] Arguments properly escaped
- [ ] Input validation strict

Example GOOD:
✅ cmd := exec.Command("ping", "-c", "1", validatedIP)

Example BAD:
❌ cmd := exec.Command("sh", "-c", userInput)
❌ exec.Command("bash", userScript)

Auto-REJECT if:
- User input directly in Command()
- Using shell: sh -c, bash -c
- No input validation
```

#### 5. Path Traversal
```
CRITICAL if code contains: os.Open, ioutil.ReadFile, filepath.Join

Check:
- [ ] Path cleaned with filepath.Clean()
- [ ] Path validated against whitelist
- [ ] No ../ allowed
- [ ] Chroot/jail if needed

Example GOOD:
✅ cleanPath := filepath.Clean(userPath)
✅ if !strings.HasPrefix(cleanPath, allowedDir) { return err }

Example BAD:
❌ os.Open(userPath)
❌ ioutil.ReadFile(req.FilePath)

Auto-COMMENT if:
- Direct use of user input in file paths
- Missing path validation
```

---

## 🧪 Test Coverage Requirements

### Critical Components (MUST have >80%):
```
internal/sentry/patterns.go          # 80%+ required
internal/core/storage.go             # 80%+ required
internal/turret/firewall.go          # 80%+ required (Phase 3)
internal/interceptor/waf.go          # 80%+ required (Phase 6)
```

### Important Components (SHOULD have >70%):
```
internal/sentry/logwatcher.go        # 70%+ recommended
internal/core/receiver.go            # 70%+ recommended
cmd/wt-*/main.go                     # 70%+ recommended
```

### Check Command:
```bash
go test -cover ./internal/sentry/
# Look for: coverage: XX.X% of statements

Auto-COMMENT if:
- Coverage <80% for critical files
- Coverage <70% for important files
- New code added without tests
```

---

## 📋 PR Review Prompts for Codex

### Prompt 1: General Security Review
```markdown
Review this PR for security issues:

Files changed: [list]

Security checks:
1. Input validation - any missing?
2. SQL injection - parameterized queries used?
3. Command injection - user input in exec()?
4. Path traversal - paths validated?
5. ReDoS - unsafe regex patterns?
6. Hardcoded secrets - credentials in code?

For each issue found:
- Severity: Critical/High/Medium/Low
- Location: file:line
- Description: what's wrong
- Fix: how to fix
- Example: good code vs bad code
```

### Prompt 2: SQL Injection Focus (storage.go)
```markdown
CRITICAL: This PR modifies database code.

Review ONLY for SQL injection:

1. Find every db.Query(), db.Exec(), db.QueryRow()
2. Check if using parameterized queries ($1, $2, ...)
3. Flag ANY string concatenation in SQL
4. Check if SQL injection tests exist

Output format:
✅ SAFE: Line 45 - Uses parameterized query
❌ UNSAFE: Line 78 - String concatenation in SQL
⚠️ MISSING: No SQL injection test found

If ANY ❌ UNSAFE found: REQUEST CHANGES
If ⚠️ MISSING found: COMMENT
If all ✅ SAFE: APPROVE
```

### Prompt 3: Pattern Matcher Review (patterns.go)
```markdown
Review regex patterns for security:

For each pattern:
1. Test with ReDoS payload: (a+)+
2. Check for nested quantifiers
3. Verify timeout configured
4. Check false positive tests exist

Pattern analysis:
- Pattern name: [name]
- Regex: [regex]
- ReDoS risk: Yes/No/Maybe
- Recommendation: [fix if needed]

Auto-REJECT if:
- High ReDoS risk
- No timeout
- Missing performance tests
```

### Prompt 4: Test Coverage Review
```markdown
Check test coverage for changed files:

Critical files changed: [list]

For each:
1. Run: go test -cover ./path/to/file
2. Parse coverage percentage
3. Check if >80% (critical) or >70% (important)

Output:
File: internal/sentry/patterns.go
Coverage: 85.2% ✅ PASS
Tests: [list test functions]

File: internal/core/storage.go
Coverage: 65.3% ❌ FAIL (need 80%+)
Missing tests: [suggest what to test]

Auto-COMMENT if coverage below threshold
```

---

## 🔄 Commit Review (Real-time)

### When Codex Should Comment on Commits:

#### Trigger 1: Commit touches critical file
```
If commit modifies:
- **/patterns.go
- **/storage.go
- **/firewall.go
- **/auth*.go

Then: Run security scan immediately
```

#### Trigger 2: Commit adds new SQL query
```
If commit diff contains:
- "db.Query"
- "db.Exec"
- "INSERT INTO"
- "UPDATE"
- "DELETE FROM"

Then: Check for parameterized queries
```

#### Trigger 3: Commit adds new regex
```
If commit diff contains:
- regexp.MustCompile
- regexp.Compile
- Regex:

Then: Check for ReDoS
```

### Commit Comment Format:
```
🤖 Security Scan Results

File: internal/core/storage.go
Issue: Potential SQL injection
Line: 78
Code: query := fmt.Sprintf("INSERT ...")

❌ CRITICAL: String concatenation in SQL query

Fix:
query := `INSERT INTO events VALUES ($1, $2)`
db.Exec(query, event.AgentId, event.Type)

Learn more: https://owasp.org/www-community/attacks/SQL_Injection
```

---

## 📊 Review Metrics to Track

### Track These Over Time:
```
1. Issues found per PR: X
2. Critical vulnerabilities caught: Y
3. Time to fix issues: Z hours
4. False positive rate: N%
5. Coverage improvements: +X%

Monthly Report:
- Total PRs reviewed: N
- Security issues found: X
- All fixed before merge: Yes/No
- Average coverage: XX%
```

---

## 🚨 Auto-Reject Conditions

**Immediately REQUEST CHANGES if:**

1. **SQL Injection Risk**
   - Any non-parameterized query
   - String concatenation in SQL
   - Missing SQL injection tests

2. **Command Injection**
   - User input in exec.Command()
   - Using shell: sh -c, bash -c
   - No input validation

3. **Hardcoded Secrets**
   - Password in code
   - API key in code
   - Private key in code

4. **Critical Test Coverage**
   - storage.go <80%
   - patterns.go <80%
   - firewall.go <80%

**Comment Format:**
```
🛑 AUTO-REJECT: Critical Security Issue

Severity: CRITICAL
Issue: SQL Injection vulnerability
File: internal/core/storage.go:78

This PR CANNOT be merged until fixed.

Required changes:
1. Use parameterized queries ($1, $2, ...)
2. Add SQL injection tests
3. Re-run security scan

/cc @security-team
```

---

## 🎯 Phase-Specific Reviews

### Phase 1 (Current): Log Monitoring
```
Focus on:
- Pattern matcher (ReDoS, false positives)
- Database layer (SQL injection)
- Input validation (log parsing)
```

### Phase 2: Communication
```
Focus on:
- mTLS implementation
- Certificate validation
- Encryption at rest
```

### Phase 3: Turret (IPS)
```
Focus on:
- Firewall rule validation
- Self-ban prevention (CRITICAL!)
- iptables command injection
```

### Phase 4: Anomaly Detection
```
Focus on:
- ML model security
- Training data poisoning
- Adversarial inputs
```

### Phase 6: Interceptor (WAF)
```
Focus on:
- Rate limiting bypass
- WAF rule evasion
- Header injection
```

---

## 🛠️ Configuration Files

### 1. .github/workflows/codex-review.yml
```yaml
name: Codex Security Review

on:
  pull_request:
    paths:
      - 'internal/sentry/patterns.go'
      - 'internal/core/storage.go'
      - 'internal/turret/**'
      - 'internal/interceptor/**'

jobs:
  security-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Codex Security Scan
        uses: github/copilot-security-scan@v1
        with:
          focus: security
          severity: high,critical
```

### 2. .github/CODEOWNERS
```
# Critical files require security review
/internal/sentry/patterns.go    @security-team
/internal/core/storage.go       @security-team @database-team
/internal/turret/firewall.go    @security-team @network-team
```

### 3. .github/pr-review-checklist.md
```
## PR Review Checklist (for Codex)

Security:
- [ ] No SQL injection
- [ ] No command injection
- [ ] No path traversal
- [ ] Input validated
- [ ] No hardcoded secrets

Tests:
- [ ] Critical files >80% coverage
- [ ] Important files >70% coverage
- [ ] Security tests included

Code Quality:
- [ ] Follows Go conventions
- [ ] Proper error handling
- [ ] No race conditions
```

---

## 📖 Example Reviews

### Example 1: Good PR (Auto-Approve)
```
✅ Security Review: PASSED

Files reviewed:
- internal/sentry/metrics.go ✅

Checks:
✅ No security issues found
✅ Test coverage: 85.4%
✅ All tests pass
✅ No race conditions

Recommendation: APPROVE

Great work! 🎉
```

### Example 2: Issues Found (Request Changes)
```
⚠️ Security Review: ISSUES FOUND

Files reviewed:
- internal/core/storage.go ❌

Critical Issues:
❌ SQL Injection (Line 78)
   query := fmt.Sprintf("INSERT INTO events VALUES ('%s')", agentId)
   
   Fix: Use parameterized query
   query := `INSERT INTO events VALUES ($1)`
   db.Exec(query, agentId)

❌ Missing SQL injection tests
   Required: TestStorage_SQLInjection()

Coverage Issues:
⚠️ Coverage: 65.2% (need 80%+)
   Missing tests for error paths

Recommendation: REQUEST CHANGES

Please fix critical issues before merge.
```

### Example 3: ReDoS Warning
```
⚠️ Pattern Security Review

File: internal/sentry/patterns.go
Pattern: PATH_TRAVERSAL

Issue: Potential ReDoS
Regex: (\.\./|\.\.\\)+
Risk: HIGH (nested quantifier)

Attack payload:
../../../../../../../../../../../X

Recommended fix:
1. Add input length limit (max 1KB)
2. Add timeout (100ms)
3. Simplify regex: (\.\./|\.\.\\)

Test needed:
func TestPattern_ReDoS(t *testing.T) {
    longPath := strings.Repeat("../", 1000) + "X"
    // Should complete in <100ms
}
```

---

## 🚀 Quick Start for GitHub Codex

### Setup Steps:

1. **Install GitHub Copilot** (if not already)
   ```bash
   # In repository settings → Copilot → Enable
   ```

2. **Add this file to repo**
   ```bash
   cp GITHUB-CODEX-CONFIG.md .github/copilot-instructions.md
   git add .github/copilot-instructions.md
   git commit -m "chore: add Codex security review config"
   ```

3. **Create first review PR**
   ```bash
   # Make a change to patterns.go
   # Create PR
   # Codex will auto-review based on these instructions
   ```

4. **Customize for your needs**
   - Adjust coverage thresholds
   - Add project-specific patterns
   - Define your security priorities

---

## 📞 Support & Feedback

**If Codex review is:**
- Too strict: Adjust thresholds in this file
- Too lenient: Add more checks
- Missing issues: Report false negatives
- False positives: Update patterns

**Contact:** @your-github-username

---

**Version:** 1.0  
**Last Updated:** 2026-02-09  
**Next Review:** After Phase 3 (Turret implementation)
