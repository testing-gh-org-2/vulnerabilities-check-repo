# Vulnerable Node.js Application for Security Testing

⚠️ **WARNING**: This application contains intentional security vulnerabilities for testing purposes only. DO NOT deploy to production!

## Vulnerabilities Included

### 1. SQL Injection (CWE-89)
- **Location**: `/api/user` endpoint
- **CWE**: CWE-89 - Improper Neutralization of Special Elements used in an SQL Command
- **CVE Reference**: CVE-2021-41773
- **Description**: User input is directly concatenated into SQL query without sanitization
- **Test**: `http://localhost:3000/api/user?id=1' OR '1'='1`

### 2. Command Injection (CWE-78)
- **Location**: `/api/ping` endpoint
- **CWE**: CWE-78 - Improper Neutralization of Special Elements used in an OS Command
- **CVE Reference**: CVE-2021-44228
- **Description**: Unsanitized user input is passed to exec() command
- **Test**: `http://localhost:3000/api/ping?host=localhost;cat /etc/passwd`

### 3. Cross-Site Scripting (CWE-79)
- **Location**: `/welcome` endpoint
- **CWE**: CWE-79 - Improper Neutralization of Input During Web Page Generation
- **CVE Reference**: CVE-2020-5902
- **Description**: User input is rendered in HTML without escaping
- **Test**: `http://localhost:3000/welcome?name=<script>alert('XSS')</script>`

### 4. Insecure Deserialization (CWE-502)
- **Location**: `/api/profile` endpoint (POST)
- **CWE**: CWE-502 - Deserialization of Untrusted Data
- **CVE Reference**: CVE-2017-5638
- **Description**: node-serialize unserialize() can execute arbitrary code
- **Test**: Send POST request with malicious serialized payload

### 5. Path Traversal (CWE-22)
- **Location**: `/api/file` endpoint
- **CWE**: CWE-22 - Improper Limitation of a Pathname to a Restricted Directory
- **CVE Reference**: CVE-2019-0708
- **Description**: No validation of file paths allows directory traversal
- **Test**: `http://localhost:3000/api/file?name=../../../etc/passwd`

## Installation

```bash
# Install dependencies
npm install

# Run the vulnerable application
npm start
```

The server will start on `http://localhost:3000`

## Testing the Vulnerabilities

### SQL Injection Example
```bash
curl "http://localhost:3000/api/user?id=1' OR '1'='1"
```

### Command Injection Example
```bash
curl "http://localhost:3000/api/ping?host=localhost;whoami"
```

### XSS Example
Open in browser: `http://localhost:3000/welcome?name=<img src=x onerror=alert('XSS')>`

### Path Traversal Example
```bash
curl "http://localhost:3000/api/file?name=../../../../etc/passwd"
```

### Insecure Deserialization Example
```bash
curl -X POST http://localhost:3000/api/profile \
  -H "Content-Type: application/json" \
  -d '{"data":"_$$ND_FUNC$$_function(){require(\"child_process\").exec(\"ls\", function(error, stdout, stderr) { console.log(stdout) });}()"}'
```

## Remediation Notes

For production code, these vulnerabilities should be fixed:

1. **SQL Injection**: Use parameterized queries or ORM
2. **Command Injection**: Validate inputs, use safe APIs, avoid shell execution
3. **XSS**: Use template engines with auto-escaping, sanitize user input
4. **Insecure Deserialization**: Use JSON.parse() instead of node-serialize, validate data
5. **Path Traversal**: Validate file paths, use allowlists, normalize paths
6. **Hard-coded Credentials**: Use environment variables and secrets management
