# Vulnerable http4k Application for CodeQL Model Testing

## ⚠️ WARNING
This application contains **INTENTIONAL SECURITY VULNERABILITIES** for testing purposes.
**DO NOT** deploy this application in any production environment or expose it to the internet.

## Purpose

This application is designed to test CodeQL custom models for the http4k library. It demonstrates realistic vulnerable code patterns that should be detected when proper models are in place.

## Vulnerabilities Included

### 1. SQL Injection (2 variants)
- **Endpoint**: `GET /api/user?id=<value>`
- **Flow**: `Request.query()` → SQL execution
- **Expected Query**: `java/sql-injection`

- **Endpoint**: `GET /api/profile?username=<value>`
- **Flow**: `Query.required()` lens → SQL execution
- **Expected Query**: `java/sql-injection`

### 2. Cross-Site Scripting (2 variants)
- **Endpoint**: `POST /api/echo` (with body)
- **Flow**: `Body.string().toLens().extract()` → `Response.body()`
- **Expected Query**: `java/xss`

- **Endpoint**: `POST /api/search?q=<value>`
- **Flow**: `Query.defaulted()` lens → `Response.body()` (HTML)
- **Expected Query**: `java/xss`

### 3. Path Traversal (2 variants)
- **Endpoint**: `GET /api/file?path=<value>`
- **Flow**: `Request.query()` → File system access
- **Expected Query**: `java/path-injection`

- **Endpoint**: `GET /api/download?file=<value>`
- **Flow**: `Request.query()` → `Uri.of()` → File system access
- **Expected Query**: `java/path-injection`

### 4. HTTP Header Injection
- **Endpoint**: `GET /api/set-header?value=<value>`
- **Flow**: `Request.query()` → `Response.header()`
- **Expected Query**: `java/http-response-splitting`

### 5. Open Redirect
- **Endpoint**: `GET /redirect?url=<value>`
- **Flow**: `Request.query()` → `Response()` with redirect status
- **Expected Query**: `java/unvalidated-url-redirection`

### 6. Command Injection
- **Endpoint**: `GET /api/ping?host=<value>`
- **Flow**: `Query.defaulted()` → `Runtime.exec()`
- **Expected Query**: `java/command-injection`

## http4k Functions Exercised

This application uses the following http4k functions that should be modeled:

- ✅ `org.http4k.core.Request.query()`
- ✅ `org.http4k.lens.LensExtractor.extract()`
- ✅ `org.http4k.core.Response.body()`
- ✅ `org.http4k.core.Response.header()`
- ✅ `org.http4k.core.Response$Companion` (constructor)
- ✅ `org.http4k.core.Status$Companion` (getters like `FOUND`, `OK`)
- ✅ `org.http4k.core.Uri$Companion.of()`
- ✅ `org.http4k.lens.Query.required()`
- ✅ `org.http4k.lens.Query.defaulted()`
- ✅ `org.http4k.lens.LensBuilder.defaulted$default()`

## Building and Running

### Prerequisites
- JDK 17 or higher
- Gradle (or use included wrapper)

### Build
```bash
./gradlew build #build failed? './gradlew clean assemble' should do the trick
```

### Run
```bash
./gradlew run
```

The server will start on `http://localhost:8080`

## Testing with CodeQL

### Step 1: Create CodeQL Database
```bash
# Build the project first
./gradlew clean assemble

# Create CodeQL database
codeql database create vulnerable-http4k-db \
  --language=java \
  --command="./gradlew clean build" \
  --source-root=.
```

### Step 2: Baseline Scan (Without Custom Models)
```bash
# Run security queries with default models
codeql database analyze vulnerable-http4k-db \
  codeql/java-queries:codeql-suites/java-security-and-quality.qls \
  --format=sarif-latest \
  --output=baseline-results.sarif

# View results
codeql github upload-results \
  --repository=<your-repo> \
  --ref=refs/heads/main \
  --commit=<commit-sha> \
  --sarif=baseline-results.sarif
```

**Expected Result**: Few or no alerts related to http4k code (since http4k is not modeled by default). You may see alerts for standard Java/JDBC code.

### Step 3: Scan with Custom Models
```bash
# Place your models in: .github/codeql/extensions/http4k/models.yml
# Or use --additional-packs flag

codeql database analyze vulnerable-http4k-db \
  codeql/java-queries:codeql-suites/java-security-and-quality.qls \
  --format=sarif-latest \
  --output=with-models-results.sarif
```

**Expected Result**: Multiple alerts corresponding to the vulnerabilities listed above.

### Step 4: Compare Results
```bash
# Count alerts in each scan
grep -c '"level": "error"' baseline-results.sarif
grep -c '"level": "error"' with-models-results.sarif

# Or use CodeQL CLI
codeql bqrs decode baseline-results.bqrs --format=csv > baseline.csv
codeql bqrs decode with-models-results.bqrs --format=csv > with-models.csv
```

## Expected Outcomes

| Vulnerability Type | Without Models | With Correct Models |
|-------------------|----------------|---------------------|
| SQL Injection (via Request.query) | ❌ Not detected | ✅ Should detect |
| SQL Injection (via lens) | ❌ Not detected | ✅ Should detect |
| XSS (via lens + body) | ❌ Not detected | ✅ Should detect |
| XSS (via defaulted lens) | ❌ Not detected | ✅ Should detect |
| Path Traversal (direct) | ❌ Not detected | ✅ Should detect |
| Path Traversal (via Uri.of) | ❌ Not detected | ✅ Should detect |
| Header Injection | ❌ Not detected | ✅ Should detect |
| Open Redirect | ❌ Not detected | ✅ Should detect |
| Command Injection | ❌ Not detected | ✅ Should detect |

## Model Types Required

To detect all vulnerabilities, you need:

### Sources (Remote Flow Sources)
- `Request.query(String)` → returns tainted String
- `LensExtractor.extract(Request)` → returns tainted value
- `Query.required(String)` → lens that extracts tainted value
- `Query.defaulted(String, T)` → lens that extracts tainted value

### Summaries (Taint Propagators)
- `Uri$Companion.of(String)` → `Argument[0] → ReturnValue`
- `LensBuilder.defaulted$default(...)` → propagates taint through lens
- `Response.body(...)` → `Argument[0] → Qualifier` (if modeling fluent API)
- `Response.header(...)` → `Argument[1] → Qualifier`

### Sinks
- `Response.body(String)` → XSS sink (Argument[0])
- `Response.header(String, String)` → Header injection sink (Argument[1])
- `Response(Status)` with redirect status → Open redirect (when Location header set)

## Troubleshooting

### No Alerts After Adding Models

1. **Check model format**: Ensure YAML syntax is correct
2. **Verify model location**: Models should be in `.github/codeql/extensions/<library-name>/`
3. **Check method signatures**: Kotlin synthetic methods (`$default`, `$Companion`) must match exactly
4. **Enable debug logging**: Run CodeQL with `--verbosity=debug`

### Too Many False Positives

1. **Refine sink definitions**: Make sinks more specific (e.g., only HTML responses for XSS)
2. **Add sanitizers**: Model sanitization functions that neutralize taint
3. **Check taint propagation**: Ensure summaries only propagate where appropriate

### Verifying Models

```bash
# Check if models are loaded
codeql resolve extensions --additional-packs=./codeql-models

# Test a specific query
codeql query run \
  --database=vulnerable-http4k-db \
  --additional-packs=./codeql-models \
  <path-to-ql-query>
```

## License

This code is provided for educational and testing purposes only.

## Author

Created for CodeQL model validation testing.