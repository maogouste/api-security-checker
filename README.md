# API Security Checker

A fast, modern API security scanner for REST and GraphQL APIs.

## Features

- **API Vulnerability Scanning**
  - Authentication weaknesses (OWASP API2)
  - Broken Object Level Authorization (OWASP API1)
  - SQL and Command Injection (OWASP API8)
  - GraphQL-specific vulnerabilities (G01-G05)

- **Reconnaissance**
  - Exposed sensitive files (.env, .git, backups)
  - Common endpoints discovery (admin, debug, metrics)
  - Security headers analysis

- **Reporting**
  - Rich console output
  - JSON export for CI/CD integration

## Installation

```bash
# Clone the repository
git clone https://github.com/youruser/api-security-checker.git
cd api-security-checker

# Install with pip
pip install -e .

# Or with dependencies
pip install -e ".[dev]"
```

## Usage

### Basic Scan

```bash
# Scan an API
apisec scan http://localhost:8000

# With authentication testing
apisec scan http://localhost:8000 -u admin -p password123

# Specific scan type
apisec scan http://localhost:8000 --type graphql

# Export to JSON
apisec scan http://localhost:8000 -o report.json
```

### VulnAPI Quick Scan

```bash
# Scan VulnAPI with preset config
apisec vulnapi

# Different backend
apisec vulnapi --backend express
apisec vulnapi --backend go
```

### Scan Types

| Type | Description |
|------|-------------|
| `all` | Run all scanners (default) |
| `api` | API vulnerability scanners only |
| `recon` | Reconnaissance scanners only |
| `auth` | Authentication scanners |
| `injection` | Injection scanners |
| `graphql` | GraphQL scanners |
| `headers` | Security headers |
| `files` | Known files discovery |
| `endpoints` | Endpoint discovery |

### List Scanners

```bash
apisec list-scanners
```

## Scanners

| Scanner | Vulnerabilities | OWASP |
|---------|-----------------|-------|
| AuthScanner | User enumeration, weak JWT, no rate limiting | API2, API4 |
| BOLAScanner | Broken Object Level Authorization | API1 |
| InjectionScanner | SQL injection, Command injection | API8 |
| GraphQLScanner | Introspection, depth, batching, auth bypass | API1-API4 |
| HeadersScanner | Missing security headers, CORS | API7 |
| KnownFilesScanner | .env, .git, backups, configs | - |
| EndpointsScanner | Admin, debug, metrics endpoints | - |

## Configuration

Create a YAML config file for your target:

```yaml
name: MyAPI
base_url: http://api.example.com

valid_username: testuser
valid_password: testpass
login_endpoint: /auth/login

graphql_endpoint: /graphql
```

Use with:

```bash
apisec scan http://api.example.com -c config/myapi.yaml
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No vulnerabilities found |
| 1 | Low/Medium vulnerabilities found |
| 2 | Critical/High vulnerabilities found |

## Integration with VulnAPI

This tool is designed to work with [VulnAPI](https://github.com/youruser/vulnapi), an intentionally vulnerable API for security learning.

```bash
# Start VulnAPI
cd vulnapi && uvicorn app.main:app --port 8000

# Scan it
apisec vulnapi
```

## License

MIT
