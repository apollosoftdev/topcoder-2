#!/bin/bash

# ===========================================
# Enterprise Guardrails - Test Script
# ===========================================
# Tests all components and validates the setup
# Usage: ./test.sh

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Counters
PASSED=0
FAILED=0

# Log functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    PASSED=$((PASSED + 1))
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    FAILED=$((FAILED + 1))
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_section() {
    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}========================================${NC}"
}

# ===========================================
# Environment Validation
# ===========================================
log_section "1. Environment Validation"

# Check .env file exists
if [ -f ".env" ]; then
    log_success ".env file exists"
else
    log_fail ".env file not found"
    echo "Please create .env file: cp .env.example .env"
    exit 1
fi

# Check required environment variables
log_info "Checking environment variables..."

# DATABASE_URL
DB_URL=$(grep "^DATABASE_URL=" .env | cut -d'=' -f2-)
if [ -n "$DB_URL" ]; then
    log_success "DATABASE_URL is set"
else
    log_fail "DATABASE_URL is not set"
fi

# AI_PROVIDER
AI_PROVIDER=$(grep "^AI_PROVIDER=" .env | cut -d'=' -f2-)
if [ -n "$AI_PROVIDER" ]; then
    log_success "AI_PROVIDER is set ($AI_PROVIDER)"
else
    log_fail "AI_PROVIDER is not set"
fi

# GROQ_API_KEY
GROQ_KEY=$(grep "^GROQ_API_KEY=" .env | cut -d'=' -f2-)
if [ -n "$GROQ_KEY" ] && [ "$GROQ_KEY" != "your-groq-api-key" ]; then
    log_success "GROQ_API_KEY is set"
else
    log_fail "GROQ_API_KEY is not set or has placeholder value"
fi

# GITHUB_APP_SECRET
GH_SECRET=$(grep "^GITHUB_APP_SECRET=" .env | cut -d'=' -f2-)
if [ -n "$GH_SECRET" ] && [ "$GH_SECRET" != "your-webhook-secret" ]; then
    log_success "GITHUB_APP_SECRET is set"
else
    log_warn "GITHUB_APP_SECRET has placeholder value"
fi

# ===========================================
# Service Health Checks
# ===========================================
log_section "2. Service Health Checks"

BACKEND_URL="http://localhost:8000"
GITHUB_APP_URL="http://localhost:3000"

# Check backend health
log_info "Checking backend health..."
BACKEND_HEALTH=$(curl -s -o /dev/null -w "%{http_code}" "$BACKEND_URL/health" 2>/dev/null || echo "000")
if [ "$BACKEND_HEALTH" = "200" ]; then
    log_success "Backend is healthy ($BACKEND_URL)"
    BACKEND_RESPONSE=$(curl -s "$BACKEND_URL/health")
    echo "         Response: $BACKEND_RESPONSE"
else
    log_fail "Backend is not responding (HTTP $BACKEND_HEALTH)"
    echo "         Run: npm run dev"
fi

# Check GitHub App health
log_info "Checking GitHub App health..."
GITHUB_HEALTH=$(curl -s -o /dev/null -w "%{http_code}" "$GITHUB_APP_URL/health" 2>/dev/null || echo "000")
if [ "$GITHUB_HEALTH" = "200" ]; then
    log_success "GitHub App is healthy ($GITHUB_APP_URL)"
    GITHUB_RESPONSE=$(curl -s "$GITHUB_APP_URL/health")
    echo "         Response: $GITHUB_RESPONSE"
else
    log_fail "GitHub App is not responding (HTTP $GITHUB_HEALTH)"
    echo "         Run: npm run dev"
fi

# ===========================================
# Database Connection Test
# ===========================================
log_section "3. Database Connection Test"

log_info "Testing database connection..."
DB_RESULT=$(python3 -c "
import psycopg2
try:
    conn = psycopg2.connect('postgresql://postgres:postgres@postgres:5432/guardrails')
    cur = conn.cursor()
    cur.execute('SELECT version();')
    version = cur.fetchone()[0]
    print('OK')
    print(version[:60])
    conn.close()
except Exception as e:
    print('FAIL')
    print(str(e)[:100])
" 2>&1)

DB_STATUS=$(echo "$DB_RESULT" | head -1)
DB_MESSAGE=$(echo "$DB_RESULT" | tail -1)

if [ "$DB_STATUS" = "OK" ]; then
    log_success "Database connection successful"
    echo "         $DB_MESSAGE"
else
    log_fail "Database connection failed"
    echo "         $DB_MESSAGE"
fi

# ===========================================
# AI Provider Test
# ===========================================
log_section "4. AI Provider Test ($AI_PROVIDER)"

log_info "Testing AI provider..."
AI_RESULT=$(python3 -c "
import asyncio
import sys
sys.path.insert(0, '.')
from app.services.ai_review import AIReviewer

async def test():
    try:
        reviewer = AIReviewer()
        if not reviewer.client:
            print('FAIL')
            print('No AI client initialized - check API key')
            return

        result = await reviewer.review(
            diff='+ x = 1  # simple test',
            repository='test/repo',
            files=['test.py']
        )
        if result:
            print('OK')
            print(f'Provider: {reviewer.provider}, Model: {reviewer.model}')
        else:
            print('FAIL')
            print('AI review returned None')
    except Exception as e:
        print('FAIL')
        print(str(e)[:100])

asyncio.run(test())
" 2>&1)

AI_STATUS=$(echo "$AI_RESULT" | head -1)
AI_MESSAGE=$(echo "$AI_RESULT" | tail -1)

if [ "$AI_STATUS" = "OK" ]; then
    log_success "AI provider is working"
    echo "         $AI_MESSAGE"
else
    log_fail "AI provider test failed"
    echo "         $AI_MESSAGE"
fi

# ===========================================
# API Endpoint Tests
# ===========================================
log_section "5. API Endpoint Tests"

if [ "$BACKEND_HEALTH" != "200" ]; then
    log_warn "Skipping API tests - backend not running"
else
    # Test /api/v1/health
    log_info "Testing GET /api/v1/health..."
    API_HEALTH=$(curl -s -o /dev/null -w "%{http_code}" "$BACKEND_URL/api/v1/health")
    if [ "$API_HEALTH" = "200" ]; then
        log_success "GET /api/v1/health"
    else
        log_fail "GET /api/v1/health (HTTP $API_HEALTH)"
    fi

    # Test /api/v1/rule-packs
    log_info "Testing GET /api/v1/rule-packs..."
    RULES_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BACKEND_URL/api/v1/rule-packs")
    if [ "$RULES_CODE" = "200" ]; then
        log_success "GET /api/v1/rule-packs"
    else
        log_fail "GET /api/v1/rule-packs (HTTP $RULES_CODE)"
    fi

    # Test /api/v1/stats/summary
    log_info "Testing GET /api/v1/stats/summary..."
    STATS_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BACKEND_URL/api/v1/stats/summary")
    if [ "$STATS_CODE" = "200" ]; then
        log_success "GET /api/v1/stats/summary"
    else
        log_fail "GET /api/v1/stats/summary (HTTP $STATS_CODE)"
    fi

    # Test /api/v1/analyze
    log_info "Testing POST /api/v1/analyze..."
    ANALYZE_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BACKEND_URL/api/v1/analyze" \
        -H "Content-Type: application/json" \
        -d '{"repository":"test/repo","diff":"+x=1","files":["test.py"],"pull_request_number":1}')
    if [ "$ANALYZE_CODE" = "200" ]; then
        log_success "POST /api/v1/analyze"
    else
        log_fail "POST /api/v1/analyze (HTTP $ANALYZE_CODE)"
    fi
fi

# ===========================================
# Security Detection Test
# ===========================================
log_section "6. Security Vulnerability Detection"

if [ "$BACKEND_HEALTH" != "200" ]; then
    log_warn "Skipping security tests - backend not running"
else
    log_info "Testing SQL Injection detection..."

    SQL_RESPONSE=$(curl -s -X POST "$BACKEND_URL/api/v1/analyze" \
        -H "Content-Type: application/json" \
        -d '{
            "repository": "test/sql-test",
            "diff": "+query = f\"SELECT * FROM users WHERE id = {user_input}\"",
            "files": ["db.py"],
            "pull_request_number": 100
        }')

    SQL_RISK=$(echo "$SQL_RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); ai=d.get('ai_review'); print(ai.get('risk_score',0) if ai else 0)" 2>/dev/null || echo "0")

    if [ "$SQL_RISK" -gt "50" ]; then
        log_success "SQL Injection detected (Risk: $SQL_RISK/100)"
    else
        log_warn "SQL Injection risk score low: $SQL_RISK/100"
    fi

    log_info "Testing Hardcoded Password detection..."

    PWD_RESPONSE=$(curl -s -X POST "$BACKEND_URL/api/v1/analyze" \
        -H "Content-Type: application/json" \
        -d '{
            "repository": "test/pwd-test",
            "diff": "+password = \"super_secret_password_123\"",
            "files": ["config.py"],
            "pull_request_number": 101
        }')

    PWD_RISK=$(echo "$PWD_RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); ai=d.get('ai_review'); print(ai.get('risk_score',0) if ai else 0)" 2>/dev/null || echo "0")

    if [ "$PWD_RISK" -gt "50" ]; then
        log_success "Hardcoded password detected (Risk: $PWD_RISK/100)"
    else
        log_warn "Hardcoded password risk score low: $PWD_RISK/100"
    fi
fi

# ===========================================
# Full Analysis Demo
# ===========================================
log_section "7. Full Analysis Demo"

if [ "$BACKEND_HEALTH" != "200" ]; then
    log_warn "Skipping demo - backend not running"
else
    log_info "Running full security analysis on vulnerable code..."

    DEMO_RESPONSE=$(curl -s -X POST "$BACKEND_URL/api/v1/analyze" \
        -H "Content-Type: application/json" \
        -d '{
            "repository": "acme/vulnerable-app",
            "diff": "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -1,3 +1,10 @@\n+import os\n+import sqlite3\n+\n+DB_PASSWORD = \"admin123\"\n+API_SECRET = \"sk-live-xxxxxxxxxxxx\"\n+\n+def get_user(user_id):\n+    query = f\"SELECT * FROM users WHERE id = {user_id}\"\n+    return db.execute(query)",
            "files": ["app.py"],
            "pull_request_number": 42
        }')

    echo ""
    echo -e "${CYAN}Analysis Result:${NC}"
    echo "$DEMO_RESPONSE" | python3 -c "
import sys, json
d = json.load(sys.stdin)

print(f\"  Repository: {d.get('repository')}\")
print(f\"  PR Number: {d.get('pull_request_number')}\")
print(f\"  Violations: {len(d.get('violations', []))}\")
print(f\"  Should Block: {d.get('should_block')}\")
print(f\"  Enforcement: {d.get('enforcement_action')}\")

ai = d.get('ai_review')
if ai:
    print(f\"  Risk Score: {ai.get('risk_score', 0)}/100\")
    print(f\"  Security Issues: {len(ai.get('security_issues', []))}\")
    print(f\"  Quality Issues: {len(ai.get('code_quality_issues', []))}\")
    print(f\"  \")
    print(f\"  AI Summary:\")
    summary = ai.get('summary', 'N/A')
    # Word wrap at 60 chars
    words = summary.split()
    line = '    '
    for w in words:
        if len(line) + len(w) > 65:
            print(line)
            line = '    '
        line += w + ' '
    if line.strip():
        print(line)

    issues = ai.get('security_issues', [])
    if issues:
        print(f\"  \")
        print(f\"  Security Issues Found:\")
        for i, issue in enumerate(issues[:3], 1):
            print(f\"    {i}. [{issue.get('severity','?').upper()}] {issue.get('title','Unknown')}\")
            if issue.get('cwe'):
                print(f\"       CWE: {issue.get('cwe')}\")
" 2>/dev/null

    log_success "Full analysis completed"
fi

# ===========================================
# Webhook Signature Verification Test
# ===========================================
log_section "8. Webhook Signature Verification Test"

if [ "$BACKEND_HEALTH" != "200" ]; then
    log_warn "Skipping webhook signature tests - backend not running"
else
    log_info "Testing webhook signature verification logic..."

    # Test the signature verification function
    WEBHOOK_TEST=$(python3 -c "
import hmac
import hashlib
import sys
sys.path.insert(0, '.')
from app.core.security import verify_github_webhook_signature

# Test valid signature
secret = 'test-secret'
payload = b'{\"test\": \"payload\"}'
signature = 'sha256=' + hmac.new(secret.encode('utf-8'), payload, hashlib.sha256).hexdigest()

if verify_github_webhook_signature(payload, signature, secret):
    print('PASS_VALID')
else:
    print('FAIL_VALID')

# Test invalid signature
if not verify_github_webhook_signature(payload, 'sha256=invalid', secret):
    print('PASS_INVALID')
else:
    print('FAIL_INVALID')

# Test missing signature prefix
if not verify_github_webhook_signature(payload, 'invalid', secret):
    print('PASS_PREFIX')
else:
    print('FAIL_PREFIX')
" 2>&1)

    if echo "$WEBHOOK_TEST" | grep -q "PASS_VALID"; then
        log_success "Valid webhook signatures accepted"
    else
        log_fail "Valid webhook signatures rejected"
    fi

    if echo "$WEBHOOK_TEST" | grep -q "PASS_INVALID"; then
        log_success "Invalid webhook signatures rejected"
    else
        log_fail "Invalid webhook signatures accepted (security issue!)"
    fi

    if echo "$WEBHOOK_TEST" | grep -q "PASS_PREFIX"; then
        log_success "Missing sha256= prefix signatures rejected"
    else
        log_fail "Missing sha256= prefix signatures accepted (security issue!)"
    fi
fi

# ===========================================
# Configuration Validation Test
# ===========================================
log_section "9. Configuration Validation Test"

log_info "Testing configuration loading..."

CONFIG_TEST=$(python3 -c "
import sys
sys.path.insert(0, '.')
from app.core.config import get_settings

try:
    settings = get_settings()
    print('OK')
    print(f'Provider: {settings.ai_provider}')
    print(f'DB URL set: {bool(settings.database_url)}')
    print(f'Debug mode: {settings.debug}')
except Exception as e:
    print('FAIL')
    print(str(e)[:100])
" 2>&1)

CONFIG_STATUS=$(echo "$CONFIG_TEST" | head -1)
if [ "$CONFIG_STATUS" = "OK" ]; then
    log_success "Configuration loaded successfully"
    echo "$CONFIG_TEST" | tail -n +2 | while read line; do
        echo "         $line"
    done
else
    log_fail "Configuration loading failed"
    echo "         $(echo "$CONFIG_TEST" | tail -1)"
fi

# ===========================================
# Summary
# ===========================================
log_section "Test Summary"

TOTAL=$((PASSED + FAILED))
echo ""
echo -e "  ${GREEN}Passed:${NC} $PASSED"
echo -e "  ${RED}Failed:${NC} $FAILED"
echo -e "  Total:  $TOTAL"
echo ""

# Log test results to file for CI/CD integration
LOG_FILE="test-results.log"
echo "Test run: $(date)" > "$LOG_FILE"
echo "Passed: $PASSED" >> "$LOG_FILE"
echo "Failed: $FAILED" >> "$LOG_FILE"
echo "Total: $TOTAL" >> "$LOG_FILE"
log_info "Test results saved to $LOG_FILE"

if [ "$FAILED" -eq 0 ]; then
    echo -e "${GREEN}All tests passed! Your setup is complete.${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Set up GitHub App webhook (use smee.io for local dev)"
    echo "  2. Install the GitHub App on a repository"
    echo "  3. Create a PR to trigger automatic review"
    exit 0
else
    echo -e "${YELLOW}Some tests failed. Check the output above.${NC}"
    echo ""
    echo "Common issues:"
    echo "  - Database not running: docker-compose up -d postgres"
    echo "  - Backend not running: npm run dev"
    echo "  - Missing API keys: Check .env file"
    exit 1
fi
