# API Security Checker

A fast, modern CLI tool to scan REST and GraphQL APIs for security vulnerabilities.

```
$ apisec scan http://localhost:8000 -u john -p password123

╭──────────────────────────────────────────────────────────────────────────────╮
│ API Security Scan Results                                                    │
│ http://localhost:8000                                                        │
╰──────────────────────────────────────────────────────────────────────────────╯

   Summary
 CRITICAL  2    SQL Injection, Command Injection
 HIGH      3    CORS, BOLA, Mass Assignment
 MEDIUM    5    Rate limiting, Headers, Logging
```

## Features

**API Vulnerability Scanners (OWASP API Top 10)**
- V01: Broken Object Level Authorization (BOLA/IDOR)
- V02: Authentication weaknesses (user enumeration, weak JWT, no rate limiting)
- V03: Excessive Data Exposure (sensitive fields leaked)
- V05: Mass Assignment (role escalation, hidden fields)
- V06: SQL Injection with database-specific detection
- V07: Command Injection with output pattern matching
- V09: Legacy API versions detection
- V10: Insufficient Logging analysis
- GraphQL-specific (introspection, depth, batching, auth bypass)

**Reconnaissance**
- 50+ sensitive files (.env, .git, backups, configs)
- 60+ common endpoints (admin, debug, actuator, metrics)
- Security headers analysis (CORS, CSP, HSTS)
- Endpoint fuzzing with OpenAPI spec parsing

**Output Formats**
- Rich console with colors and tables
- JSON export for automation
- HTML standalone reports
- SARIF 2.1.0 for GitHub Code Scanning

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

# Export reports
apisec scan https://api.example.com -o report.json      # JSON
apisec scan https://api.example.com --html report.html  # HTML
apisec scan https://api.example.com --sarif report.sarif # SARIF
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
| BOLAScanner | Access to other users' data | API1 |
| AuthScanner | User enumeration, weak JWT, no rate limit | API2, API4 |
| ExposureScanner | Sensitive data in responses (SSN, CC, keys) | API3 |
| MassAssignmentScanner | Role escalation, hidden field modification | API6 |
| InjectionScanner | SQL injection, Command injection | API8 |
| LegacyScanner | Deprecated API versions (/v1/, /v2/) | API9 |
| LoggingScanner | Missing security event logging | API10 |
| GraphQLScanner | Introspection, depth attacks, batching | API1-4 |
| HeadersScanner | Missing security headers, CORS issues | API7 |
| KnownFilesScanner | .env, .git, .sql, configs exposed | - |
| EndpointsScanner | /admin, /debug, /actuator, /metrics | - |
| FuzzerScanner | Hidden endpoints via OpenAPI + fuzzing | - |

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

## Use with API Security Dojo

This tool pairs perfectly with [API Security Dojo](https://github.com/maogouste/api-security-dojo), an intentionally vulnerable API for learning.

```bash
# Terminal 1: Start API Security Dojo
cd api-security-dojo/implementations/python-fastapi
hatch run serve  # http://localhost:8000

# Terminal 2: Scan it
apisec scan http://localhost:8000 -u john -p password123

# Other backends
# Go:    http://localhost:3002
# PHP:   http://localhost:3003
# Java:  http://localhost:3004
# Node:  http://localhost:3005
```

## CI/CD Integration

Use SARIF output for GitHub Code Scanning:

```yaml
# .github/workflows/api-security.yml
- name: Run API Security Scan
  run: apisec scan ${{ secrets.API_URL }} --sarif results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

See `.github/workflows/api-security-scan.yml` for a complete example.

## License

MIT
