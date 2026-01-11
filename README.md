# API Security Checker

A fast, modern CLI tool to scan REST and GraphQL APIs for security vulnerabilities.

```
$ apisec vulnapi

╭──────────────────────────────────────────────────────────────────────────────╮
│ API Security Scan Results                                                    │
│ http://localhost:8000                                                        │
╰──────────────────────────────────────────────────────────────────────────────╯

   Summary
 CRITICAL  1    SQL Injection
 HIGH      2    CORS, BOLA
 MEDIUM    5    Rate limiting, Headers
```

## Features

**API Vulnerability Scanners**
- Authentication weaknesses (user enumeration, weak JWT, no rate limiting)
- Broken Object Level Authorization (BOLA/IDOR)
- SQL and Command Injection
- GraphQL-specific (introspection, depth, batching, auth bypass)

**Reconnaissance**
- 50+ sensitive files (.env, .git, backups, configs)
- 60+ common endpoints (admin, debug, actuator, metrics)
- Security headers analysis (CORS, CSP, HSTS)

**Output**
- Rich console with colors and tables
- JSON export for CI/CD pipelines

## Installation

```bash
git clone https://github.com/maogouste/api-security-checker.git
cd api-security-checker

python3 -m venv venv
source venv/bin/activate
pip install -e .
```

## Quick Start

```bash
# Scan any API
apisec scan https://api.example.com

# With credentials for auth testing
apisec scan https://api.example.com -u admin -p secret

# Specific scan type
apisec scan https://api.example.com --type injection

# Export report
apisec scan https://api.example.com -o report.json
```

## Scan Types

| Type | Scanners |
|------|----------|
| `all` | Everything (default) |
| `api` | Auth, BOLA, Injection, GraphQL |
| `recon` | Files, Endpoints, Headers |
| `auth` | Authentication only |
| `injection` | SQLi, Command injection |
| `graphql` | GraphQL-specific |
| `headers` | Security headers |
| `files` | Sensitive files |
| `endpoints` | Common paths |

## Scanners

| Scanner | Detects | OWASP |
|---------|---------|-------|
| AuthScanner | User enumeration, weak JWT, no rate limit | API2, API4 |
| BOLAScanner | Access to other users' data | API1 |
| InjectionScanner | SQL injection, Command injection | API8 |
| GraphQLScanner | Introspection, depth attacks, batching | API1-4 |
| HeadersScanner | Missing security headers, CORS issues | API7 |
| KnownFilesScanner | .env, .git, .sql, configs exposed | - |
| EndpointsScanner | /admin, /debug, /actuator, /metrics | - |

## Configuration

Create a YAML config for targets you scan frequently:

```yaml
# config/myapi.yaml
name: My Production API
base_url: https://api.mycompany.com

valid_username: testuser
valid_password: testpass
login_endpoint: /auth/login

graphql_endpoint: /graphql
```

```bash
apisec scan https://api.mycompany.com -c config/myapi.yaml
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No vulnerabilities |
| 1 | Low/Medium findings |
| 2 | Critical/High findings |

Useful for CI/CD:
```bash
apisec scan $API_URL || exit 1
```

## Use with VulnAPI

This tool pairs perfectly with [VulnAPI](https://github.com/maogouste/vulnapi), an intentionally vulnerable API for learning.

```bash
# Terminal 1: Start VulnAPI
cd vulnapi/implementations/python-fastapi
uvicorn app.main:app

# Terminal 2: Scan it
apisec vulnapi                    # FastAPI (port 8000)
apisec vulnapi --backend express  # Express (port 3001)
apisec vulnapi --backend go       # Go/Gin (port 3002)
apisec vulnapi --backend php      # PHP (port 3003)
apisec vulnapi --backend java     # Spring Boot (port 3004)
```

## License

MIT
