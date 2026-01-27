# AI-Powered Enterprise Guardrails for GitHub Copilot

Enterprise-grade code security and compliance guardrails that integrate with GitHub to analyze pull requests using a hybrid AI + static analysis approach.

## Features

- **Static Analysis**: Pattern-based security scanning for common vulnerabilities (OWASP Top 10, CWE)
- **AI-Powered Review**: Claude API integration for intelligent, context-aware code review
- **Compliance Rule Packs**: Pre-built rules for banking (PCI-DSS, SOX), healthcare (HIPAA), and general security
- **GitHub Integration**: Native GitHub App with PR comments, check runs, and merge blocking
- **Copilot Detection**: Identifies AI-generated code for enhanced scrutiny
- **Audit Logging**: PostgreSQL-backed audit trail for compliance reporting

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│              GitHub App (TypeScript/Node.js)            │
│  - Receives PR/commit webhooks                          │
│  - Posts review comments to PRs                         │
│  - Manages check runs (block/allow merge)               │
└─────────────────────┬───────────────────────────────────┘
                      │ HTTP API calls
┌─────────────────────▼───────────────────────────────────┐
│              Backend API (Python/FastAPI)               │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐        │
│  │ Static      │ │ AI Review   │ │ Rule        │        │
│  │ Analyzer    │ │ (Claude)    │ │ Engine      │        │
│  └─────────────┘ └─────────────┘ └─────────────┘        │
└─────────────────────────────────────────────────────────┘
                      │
              ┌───────▼───────┐
              │  PostgreSQL   │
              │  (Audit Logs) │
              └───────────────┘
```

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+
- PostgreSQL 15+
- Anthropic API key
- GitHub App credentials

### Local Development

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd topcoder-2
   ```

2. **Configure environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your credentials
   ```

3. **Start with Docker Compose**
   ```bash
   docker-compose up -d
   ```

   This starts:
   - Backend API on `http://localhost:8000`
   - GitHub App on `http://localhost:3000`
   - PostgreSQL on `localhost:5432`

### Manual Setup

#### Backend (Python/FastAPI)

```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

#### GitHub App (TypeScript)

```bash
cd github-app
npm install
npm run dev
```

## Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `ANTHROPIC_API_KEY` | Claude API key for AI review | Yes |
| `DATABASE_URL` | PostgreSQL connection URL | Yes |
| `GITHUB_APP_ID` | GitHub App ID | Yes |
| `GITHUB_PRIVATE_KEY` | GitHub App private key | Yes |
| `GITHUB_WEBHOOK_SECRET` | Webhook secret for signature verification | Yes |
| `BACKEND_API_URL` | URL where backend is accessible | Yes |
| `CLAUDE_MODEL` | Claude model to use (default: claude-sonnet-4-20250514) | No |
| `DEFAULT_ENFORCEMENT_MODE` | advisory, warning, or blocking | No |

### GitHub App Setup

1. Create a new GitHub App at `https://github.com/settings/apps/new`

2. Configure the following:
   - **Webhook URL**: `https://your-domain.com/webhook`
   - **Webhook Secret**: Generate a secure secret
   - **Permissions**:
     - Repository: Read (Contents, Metadata)
     - Pull requests: Read & Write
     - Checks: Read & Write
     - Issues: Read & Write
   - **Subscribe to events**:
     - Pull request
     - Push

3. Generate and download the private key

4. Install the app on your repositories

## API Reference

### POST /api/v1/analyze

Analyze code changes for security violations.

**Request:**
```json
{
  "repository": "owner/repo",
  "pull_request_number": 123,
  "diff": "...",
  "files": ["src/main.py"],
  "config": {
    "enforcement_mode": "warning",
    "rule_packs": ["security", "banking"],
    "ai_review_enabled": true,
    "copilot_detection_enabled": true
  }
}
```

**Response:**
```json
{
  "request_id": "uuid",
  "violations": [
    {
      "type": "security",
      "severity": "high",
      "rule": "hardcoded_secret",
      "file": "config.py",
      "line": 42,
      "message": "Hardcoded API key detected",
      "suggestion": "Use environment variables instead",
      "cwe": "CWE-798",
      "owasp": "A3:2017"
    }
  ],
  "ai_review": {
    "summary": "Found security issues...",
    "risk_score": 65
  },
  "copilot_detection": {
    "detected": true,
    "confidence": 70,
    "indicators": ["Generic variable names"]
  },
  "enforcement_action": "warning",
  "should_block": false
}
```

### GET /api/v1/audit-logs

Retrieve audit logs with pagination.

**Query Parameters:**
- `repository` (optional): Filter by repository
- `page` (default: 1): Page number
- `page_size` (default: 50): Items per page

### GET /api/v1/rule-packs

List available rule packs.

### GET /api/v1/health

Health check endpoint.

## Rule Packs

### Security (Default)
General security rules based on OWASP Top 10:
- Hardcoded secrets and credentials
- SQL injection patterns
- Command injection
- XSS vulnerabilities
- Insecure deserialization
- Weak cryptography

### Banking
PCI-DSS, SOX, and GLBA compliance:
- Credit card number exposure
- SSN detection
- Bank account/routing number exposure
- Unencrypted PII storage
- Missing audit logging

### Healthcare
HIPAA and HITECH compliance:
- PHI exposure detection
- Medical record number handling
- Diagnosis code protection
- Encryption requirements
- Access control verification

## Enforcement Modes

| Mode | Behavior |
|------|----------|
| `advisory` | Comments only, no blocking |
| `warning` | Annotations + alerts, check status neutral |
| `blocking` | Prevents merge via failed check run |

## Deployment

### Railway

1. Fork this repository
2. Create a new project on Railway
3. Add a PostgreSQL database
4. Set environment variables
5. Deploy from GitHub

### Docker

```bash
docker-compose -f docker-compose.yml up -d
```

### Kubernetes

Helm charts coming soon.

## Security Patterns Detected

| Pattern | Severity | CWE |
|---------|----------|-----|
| Hardcoded API Key | Critical | CWE-798 |
| Hardcoded Password | Critical | CWE-798 |
| SQL Injection | High | CWE-89 |
| Command Injection | High | CWE-78 |
| XSS (innerHTML) | Medium | CWE-79 |
| Insecure Deserialization | High | CWE-502 |
| Weak Hash (MD5/SHA1) | Medium | CWE-328 |
| Insecure Random | Medium | CWE-330 |
| Private Key Exposure | Critical | CWE-321 |

## Project Structure

```
topcoder-2/
├── backend/                     # Python FastAPI backend
│   ├── app/
│   │   ├── api/                # API routes and schemas
│   │   ├── core/               # Configuration and security
│   │   ├── services/           # Business logic
│   │   ├── rules/              # Rule engine and packs
│   │   └── models/             # Database models
│   ├── requirements.txt
│   └── Dockerfile
│
├── github-app/                  # TypeScript GitHub App
│   ├── src/
│   │   ├── webhooks/           # Event handlers
│   │   ├── services/           # API clients
│   │   └── utils/              # Formatters
│   ├── package.json
│   └── Dockerfile
│
├── docker-compose.yml          # Local development
├── railway.toml                # Railway deployment
└── README.md
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests
5. Submit a pull request

## License

MIT License - see LICENSE file for details.
