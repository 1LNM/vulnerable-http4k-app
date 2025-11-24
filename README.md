# Vulnerable http4k Application for CodeQL Model Testing

## ⚠️ WARNING
This application contains **INTENTIONAL SECURITY VULNERABILITIES** for testing purposes.
**DO NOT** deploy this application in any production environment or expose it to the internet.

## Purpose

This application is designed to test CodeQL custom models for the http4k library. It demonstrates realistic vulnerable code patterns that should be detected when proper models are in place.

## Vulnerabilities Included

### v1 Endpoints (9 total)
Testing with http4k core functions `Request.query`, `Response.header` and `Response.body`

#### 1. SQL Injection (2 variants)
- **Endpoint**: `GET /api/user?id=<value>`
- **Flow**: `Request.query()` → SQL execution
- **Expected Query**: `java/sql-injection`

- **Endpoint**: `GET /api/profile?username=<value>`
- **Flow**: `Query.required()` lens → SQL execution
- **Expected Query**: `java/sql-injection`

#### 2. Cross-Site Scripting (2 variants)
- **Endpoint**: `POST /api/echo` (with body)
- **Flow**: `Body.string().toLens().extract()` → `Response.body()`
- **Expected Query**: `java/xss`

- **Endpoint**: `POST /api/search?q=<value>`
- **Flow**: `Query.defaulted()` lens → `Response.body()` (HTML)
- **Expected Query**: `java/xss`

#### 3. Path Traversal (2 variants)
- **Endpoint**: `GET /api/file?path=<value>`
- **Flow**: `Request.query()` → File system access
- **Expected Query**: `java/path-injection`

- **Endpoint**: `GET /api/download?file=<value>`
- **Flow**: `Request.query()` → `Uri.of()` → File system access
- **Expected Query**: `java/path-injection`

#### 4. HTTP Header Injection
- **Endpoint**: `GET /api/set-header?value=<value>`
- **Flow**: `Request.query()` → `Response.header()`
- **Expected Query**: `java/http-response-splitting`

#### 5. Open Redirect
- **Endpoint**: `GET /redirect?url=<value>`
- **Flow**: `Request.query()` → `Response()` with redirect status
- **Expected Query**: `java/unvalidated-url-redirection`

#### 6. Command Injection
- **Endpoint**: `GET /api/ping?host=<value>`
- **Flow**: `Query.defaulted()` → `Runtime.exec()`
- **Expected Query**: `java/command-injection`

### V2 Endpoints (19 total)
Testing with http4k core functions `LensExtractor.get`, `Request.header`, `Uri.getQuery`, `Body.getStream`, `HttpMessage.body`, etc.

#### 7. SQL Injection - V2 (5 variants)
- **Endpoint**: `GET /api/v2/sql/lens-get?id=<value>`
- **Flow**: `LensExtractor.get()` → SQL execution
- **Test**: SQL injection via lens getter method

- **Endpoint**: `GET /api/v2/sql/lens-extract?username=<value>`
- **Flow**: `LensExtractor.extract()` → SQL execution
- **Test**: SQL injection via lens extract method

- **Endpoint**: `GET /api/v2/sql/request-header` (Header: `X-User-ID`)
- **Flow**: `Request.header()` → SQL execution
- **Test**: SQL injection from HTTP headers

- **Endpoint**: `GET /api/v2/sql/uri-query?id=<value>`
- **Flow**: `Uri.getQuery()` → manual parsing → SQL execution
- **Test**: SQL injection via URI query string parsing

- **Endpoint**: `GET /api/v2/sql/httpmessage-header` (Header: `X-API-Key`)
- **Flow**: `HttpMessage.header()` → SQL execution
- **Test**: SQL injection via HttpMessage interface

#### 8. Cross-Site Scripting - V2 (4 variants)
- **Endpoint**: `GET /api/v2/xss/lens-injector?msg=<value>`
- **Flow**: `Request.query()` → `LensInjector.inject()` → Response
- **Test**: XSS via lens injection into response body

- **Endpoint**: `POST /api/v2/xss/httpmessage-body`
- **Flow**: `HttpMessage.body()` → HTML response
- **Test**: XSS via HttpMessage body access

- **Endpoint**: `POST /api/v2/xss/body-stream`
- **Flow**: `Body.getStream()` → read content → HTML response
- **Test**: XSS via body input stream

- **Endpoint**: `GET /api/v2/xss/to-message?data=<value>`
- **Flow**: `Request.query()` → `Response.toMessage()` → HTML
- **Test**: XSS via Response.toMessage() conversion

#### 9. Path Traversal - V2 (4 variants)
- **Endpoint**: `GET /api/v2/path/uri-path`
- **Flow**: `Request.getUri()` → `Uri.path()` → File access
- **Test**: Path traversal via URI path property

- **Endpoint**: `GET /api/v2/path/uri-getpath`
- **Flow**: `Uri.getPath()` → File access
- **Test**: Path traversal via explicit getPath() call

- **Endpoint**: `GET /api/v2/path/request-header` (Header: `X-Filename`)
- **Flow**: `Request.header()` → File path construction
- **Test**: Path traversal from HTTP headers

- **Endpoint**: `POST /api/v2/path/body-stream`
- **Flow**: `Body.getStream()` → read filename → File access
- **Test**: Path traversal via request body stream

#### 10. Header Injection - V2 (3 variants)
- **Endpoint**: `GET /api/v2/header/uri-query?value=<value>`
- **Flow**: `Uri.getQuery()` → parse → `Response.header()`
- **Test**: Header injection via URI query parsing

- **Endpoint**: `GET /api/v2/header/lens-extract?header=<value>`
- **Flow**: `LensExtractor.extract()` → `Response.header()`
- **Test**: Header injection via lens extraction

- **Endpoint**: `POST /api/v2/header/body-stream`
- **Flow**: `Body.getStream()` → read value → `Response.header()`
- **Test**: Header injection from request body stream

#### 11. Open Redirect - V2 (3 variants)
- **Endpoint**: `GET /api/v2/redirect/request-header` (Header: `X-Redirect-To`)
- **Flow**: `Request.header()` → Redirect response
- **Test**: Open redirect from HTTP headers

- **Endpoint**: `GET /api/v2/redirect/uri-query?target=<value>`
- **Flow**: `Uri.getQuery()` → parse → Redirect location
- **Test**: Open redirect via URI query parsing

- **Endpoint**: `GET /api/v2/redirect/lens-get?url=<value>`
- **Flow**: `LensExtractor.get()` → Redirect location
- **Test**: Open redirect via lens getter

#### 12. Command Injection - V2 (3 variants)
- **Endpoint**: `GET /api/v2/cmd/lens-get?host=<value>`
- **Flow**: `LensExtractor.get()` → `Runtime.exec()`
- **Test**: Command injection via lens getter

- **Endpoint**: `GET /api/v2/cmd/request-header` (Header: `X-Command`)
- **Flow**: `Request.header()` → Shell execution
- **Test**: Command injection from HTTP headers

- **Endpoint**: `GET /api/v2/cmd/httpmessage-header` (Header: `X-Target`)
- **Flow**: `HttpMessage.header()` → Command execution
- **Test**: Command injection via HttpMessage interface

## http4k Functions Exercised

This application uses the following http4k functions that should be modeled:

### Original Endpoints
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

### V2 Endpoints (Additional Functions)
- ✅ `org.http4k.lens.LensExtractor.get()` - Lens getter for extracting values
- ✅ `org.http4k.core.Request.header()` - Direct header access
- ✅ `org.http4k.core.HttpMessage.header()` - Header access via parent interface
- ✅ `org.http4k.core.Uri.getQuery()` - Raw query string access
- ✅ `org.http4k.core.Uri.path` / `Uri.getPath()` - URI path property/method
- ✅ `org.http4k.core.Request.getUri()` - URI getter
- ✅ `org.http4k.core.Body.getStream()` - Body input stream access
- ✅ `org.http4k.core.HttpMessage.body()` - Body access via parent interface
- ✅ `org.http4k.lens.LensInjector.inject()` - Lens injection into response
- ✅ `org.http4k.core.Response.toMessage()` - Response conversion

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
  --command="./gradlew clean assemble" \
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

| Vulnerability Type | Endpoint Count | Without Models | With Correct Models |
|-------------------|----------------|----------------|---------------------|
| SQL Injection (original) | 2 | ❌ Not detected | ✅ Should detect |
| SQL Injection (v2) | 5 | ❌ Not detected | ✅ Should detect |
| XSS (original) | 2 | ❌ Not detected | ✅ Should detect |
| XSS (v2) | 4 | ❌ Not detected | ✅ Should detect |
| Path Traversal (original) | 2 | ❌ Not detected | ✅ Should detect |
| Path Traversal (v2) | 4 | ❌ Not detected | ✅ Should detect |
| Header Injection (original) | 1 | ❌ Not detected | ✅ Should detect |
| Header Injection (v2) | 3 | ❌ Not detected | ✅ Should detect |
| Open Redirect (original) | 1 | ❌ Not detected | ✅ Should detect |
| Open Redirect (v2) | 3 | ❌ Not detected | ✅ Should detect |
| Command Injection (original) | 1 | ❌ Not detected | ✅ Should detect |
| Command Injection (v2) | 3 | ❌ Not detected | ✅ Should detect |
| **TOTAL** | **28 vulnerabilities** | **~0-2** | **~28** |

## Model Types Required

⚠️ Consider this as just a reference for writing your models, they might be incorrect or incomplete.

To detect all vulnerabilities, you need:

### Sources (Remote Flow Sources)
- `Request.query(String)` → returns tainted String
- `Request.header(String)` → returns tainted String
- `HttpMessage.header(String)` → returns tainted String
- `LensExtractor.extract(Request)` → returns tainted value
- `LensExtractor.get(Request)` → returns tainted value
- `Query.required(String)` → lens that extracts tainted value
- `Query.defaulted(String, T)` → lens that extracts tainted value
- `Uri.getQuery()` → returns tainted query string
- `Uri.path` / `Uri.getPath()` → returns tainted path
- `Body.getStream()` → returns tainted InputStream
- `HttpMessage.body()` → returns tainted Body

### Summaries (Taint Propagators)
- `Uri$Companion.of(String)` → `Argument[0] → ReturnValue`
- `Request.getUri()` → `Qualifier → ReturnValue`
- `LensBuilder.defaulted$default(...)` → propagates taint through lens
- `Response.body(...)` → `Argument[0] → Qualifier` (if modeling fluent API)
- `Response.header(...)` → `Argument[1] → Qualifier`
- `LensInjector.inject(...)` → `Argument[0] → ReturnValue`

### Sinks
- `Response.body(String)` → XSS sink (Argument[0])
- `Response.header(String, String)` → Header injection sink (Argument[1])
- `Response(Status)` with redirect status → Open redirect (when Location header set)
- `LensInjector.inject()` → XSS sink when content type is HTML

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