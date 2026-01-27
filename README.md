# AI-Powered Enterprise Guardrails for GitHub Copilot

Enterprise-grade code security and compliance guardrails that integrate with GitHub to analyze pull requests using a hybrid AI + static analysis approach.

## Features

- **Static Analysis**: Pattern-based security scanning for common vulnerabilities (OWASP Top 10, CWE)
- **AI-Powered Review**: Multiple AI provider support (Anthropic Claude, Google Gemini, Groq) for intelligent, context-aware code review
- **Compliance Rule Packs**: Pre-built rules for banking (PCI-DSS, SOX), healthcare (HIPAA), and general security
- **GitHub Integration**: Native GitHub App with PR comments, check runs, and merge blocking
- **Copilot Detection**: Identifies AI-generated code for enhanced scrutiny
- **Audit Logging**: PostgreSQL-backed audit trail for compliance reporting
- **License Analysis**: Detects restricted and copyleft licenses in dependencies

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│              GitHub App (TypeScript/Node.js)            │
│  - Receives PR/commit webhooks                          │
│  - Posts review comments to PRs                         │
│  - Manages check runs (block/allow merge)               │
└─────────────────────┬───────────────────────────────────┘
                      │ HTTP API calls (with timeout)
┌─────────────────────▼───────────────────────────────────┐
│              Backend API (Python/FastAPI)               │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐        │
│  │ Static      │ │ AI Review   │ │ Rule        │        │
│  │ Analyzer    │ │ (Multi-AI)  │ │ Engine      │        │
│  └─────────────┘ └─────────────┘ └─────────────┘        │
│                         │                               │
│         ┌───────────────┼───────────────┐               │
│         ▼               ▼               ▼               │
│   ┌──────────┐   ┌──────────┐   ┌──────────┐            │
│   │ Anthropic│   │  Google  │   │   Groq   │            │
│   │ (Claude) │   │ (Gemini) │   │ (Llama)  │            │
│   └──────────┘   └──────────┘   └──────────┘            │
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
- AI Provider API key (one of: Anthropic, Google, or Groq)
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

### Running Tests

The backend includes a comprehensive test script that validates your setup:

```bash
cd backend
./test.sh
```

The test script checks:

1. Environment variables configuration
2. Service health (backend and GitHub App)
3. Database connectivity
4. AI provider connectivity
5. API endpoints
6. Security vulnerability detection
7. Webhook signature verification
8. Configuration loading

Test results are saved to `test-results.log` for CI/CD integration.

## Configuration

### Environment Variables

#### Backend (Python/FastAPI)

| Variable                   | Description                                         | Required    | Default                    |
| -------------------------- | --------------------------------------------------- | ----------- | -------------------------- |
| `ENV`                      | Environment: `development`, `staging`, `production` | No          | `development`              |
| `DATABASE_URL`             | PostgreSQL connection URL                           | Yes         | -                          |
| `AI_PROVIDER`              | AI provider: `anthropic`, `gemini`, or `groq`       | No          | `groq`                     |
| `ANTHROPIC_API_KEY`        | Anthropic API key (if using Claude)                 | Conditional | -                          |
| `GOOGLE_API_KEY`           | Google API key (if using Gemini)                    | Conditional | -                          |
| `GROQ_API_KEY`             | Groq API key (if using Llama)                       | Conditional | -                          |
| `API_KEY`                  | Backend API authentication key                      | No          | -                          |
| `CORS_ORIGINS`             | Comma-separated allowed origins                     | No          | localhost                  |
| `CLAUDE_MODEL`             | Claude model                                        | No          | `claude-sonnet-4-20250514` |
| `GEMINI_MODEL`             | Gemini model                                        | No          | `gemini-2.0-flash`         |
| `GROQ_MODEL`               | Groq model                                          | No          | `llama-3.3-70b-versatile`  |
| `DEFAULT_ENFORCEMENT_MODE` | `advisory`, `warning`, or `blocking`                | No          | `warning`                  |
| `DEBUG`                    | Enable debug mode                                   | No          | `false`                    |
| `LOG_LEVEL`                | Logging level                                       | No          | `INFO`                     |

#### GitHub App (TypeScript)

| Variable                | Description                               | Required |
| ----------------------- | ----------------------------------------- | -------- | ------- |
| `GITHUB_APP_ID`         | GitHub App ID                             | Yes      |
| `GITHUB_PRIVATE_KEY`    | GitHub App private key (PEM format)       | Yes      |
| `GITHUB_WEBHOOK_SECRET` | Webhook secret for signature verification | Yes      |
| `BACKEND_API_URL`       | URL where backend is accessible           | Yes      |
| `BACKEND_API_KEY`       | API key for backend authentication        | No       |
| `BACKEND_API_TIMEOUT`   | Request timeout in milliseconds           | No       | `30000` |

#### Production Configuration

When deploying to production, ensure you set:

```bash
# Required for production
ENV=production
CORS_ORIGINS=https://your-app.com,https://admin.your-app.com
API_KEY=your-secure-api-key

# Recommended
LOG_LEVEL=WARNING
```

**Security Notes:**

- In production (`ENV=production`), warnings are logged if `CORS_ORIGINS` or `API_KEY` are not configured
- The backend validates database connectivity on startup and fails fast if unavailable
- The GitHub App validates all required environment variables at startup

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

**Response:**

```json
{
  "status": "healthy",
  "version": "1.0.0",
  "database": "connected",
  "ai_service": "available"
}
```

### POST /api/v1/override

Override a blocking decision (requires appropriate permissions).

### GET /api/v1/stats/summary

Get aggregated statistics for the dashboard.

## AI Providers

The system supports multiple AI providers for code review. Configure via the `AI_PROVIDER` environment variable.

| Provider           | Variable                | Models           | Best For                        |
| ------------------ | ----------------------- | ---------------- | ------------------------------- |
| **Groq** (default) | `AI_PROVIDER=groq`      | Llama 3.3 70B    | Fast responses, cost-effective  |
| **Anthropic**      | `AI_PROVIDER=anthropic` | Claude Sonnet    | High accuracy, nuanced analysis |
| **Google**         | `AI_PROVIDER=gemini`    | Gemini 2.0 Flash | Balanced speed and quality      |

Each provider requires its respective API key to be set.

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

| Mode       | Behavior                                   |
| ---------- | ------------------------------------------ |
| `advisory` | Comments only, no blocking                 |
| `warning`  | Annotations + alerts, check status neutral |
| `blocking` | Prevents merge via failed check run        |

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

| Pattern                  | Severity | CWE     |
| ------------------------ | -------- | ------- |
| Hardcoded API Key        | Critical | CWE-798 |
| Hardcoded Password       | Critical | CWE-798 |
| SQL Injection            | High     | CWE-89  |
| Command Injection        | High     | CWE-78  |
| XSS (innerHTML)          | Medium   | CWE-79  |
| Insecure Deserialization | High     | CWE-502 |
| Weak Hash (MD5/SHA1)     | Medium   | CWE-328 |
| Insecure Random          | Medium   | CWE-330 |
| Private Key Exposure     | Critical | CWE-321 |

## Project Structure

```
enterprise-guardrails/
├── backend/                     # Python FastAPI backend
│   ├── app/
│   │   ├── api/                # API routes and schemas
│   │   ├── core/               # Configuration and security
│   │   ├── services/           # Business logic (AI review, analysis)
│   │   ├── rules/              # Rule engine and packs
│   │   └── models/             # Database models
│   ├── requirements.txt
│   ├── test.sh                 # Comprehensive test script
│   └── Dockerfile
│
├── github-app/                  # TypeScript GitHub App
│   ├── src/
│   │   ├── webhooks/           # Event handlers (PR, push, comments)
│   │   ├── services/           # GitHub API & backend clients
│   │   └── utils/              # Comment formatters
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
