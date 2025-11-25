# CodeQL Testing Guide for http4k Models

## Overview

This guide walks through the complete testing process for validating CodeQL models for the http4k library.

## Endpoint Structure

- **v1 Endpoints** (9): Test core http4k functionality like `Request.query`, `Response.header` and `Response.body`
- **V2 Endpoints** (19): Test core http4k functionality like `LensExtractor.get`, `Request.header`, `Uri.getQuery`, `Body.getStream`, `HttpMessage.body`, etc.

## Phase 1: Setup

### 1.1 Build the Application
```bash
cd vulnerable-http4k-app
./gradlew clean build #build failed? './gradlew clean assemble' should do the trick
```

### 1.2 Create CodeQL Database
```bash
codeql database create vulnerable-http4k-db \
  --language=java \
  --command="./gradlew clean assemble --no-daemon" \
  --source-root=. \
  --overwrite
```

**Troubleshooting**:
- If build fails, ensure JDK 17+ is installed: `java -version`
- For Gradle issues: `./gradlew --version`
- Clear Gradle cache: `rm -rf ~/.gradle/caches`

## Phase 2: Baseline Analysis (No Models)

### 2.1 Run Default Security Queries
```bash
codeql database analyze vulnerable-http4k-db \
   	--format=sarif-latest \
    --sarif-category="codeql_db" \
    --output=baseline-results.sarif \
    java-security-extended
```

### 2.2 Review Baseline Results
```bash
# Count total alerts
cat baseline-results.sarif | jq '.runs[0].results | length'

# List alert types
cat baseline-results.sarif | jq '.runs[0].results[].ruleId' | sort | uniq -c

# Check for http4k-related alerts (should be minimal/none)
cat baseline-results.sarif | jq '.runs[0].results[] | select(.message.text | contains("http4k"))'
```

**Expected Baseline**:
- Possibly 0-2 alerts from standard Java code (e.g., JDBC if not parameterized)
- Should NOT detect vulnerabilities in http4k-specific code paths
- No alerts mentioning http4k functions

## Phase 3: Create Custom Models

### 3.1 Model Directory Structure
```bash
mkdir -p .github/codeql/extensions/http4k
```

### 3.2 Create Models File
Create `.github/codeql/extensions/http4k/models.yml` based on your analysis.

⚠️ Consider this as just a reference for writing your models, they might be incorrect or incomplete.

**Model Structure Example**:
```yaml
extensions:
  - addsTo:
      pack: codeql/java-all
      extensible: sourceModel
    data:
      # Example: Request.query() as remote source
      - ["org.http4k.core", "Request", true, "query", "(String)", "", "ReturnValue", "remote", "manual"]
      # Example: Request.header() as remote source (V2)
      - ["org.http4k.core", "Request", true, "header", "(String)", "", "ReturnValue", "remote", "manual"]
      # Example: LensExtractor.get() as remote source (V2)
      - ["org.http4k.lens", "LensExtractor", true, "get", "(Request)", "", "ReturnValue", "remote", "manual"]
      
  - addsTo:
      pack: codeql/java-all
      extensible: sinkModel
    data:
      # Example: Response.body() as XSS sink
      - ["org.http4k.core", "Response", true, "body", "(String)", "", "Argument[0]", "xss", "manual"]
      
  - addsTo:
      pack: codeql/java-all
      extensible: summaryModel
    data:
      # Example: Uri.of() propagates taint
      - ["org.http4k.core", "Uri$Companion", true, "of", "(String)", "", "Argument[0]", "ReturnValue", "taint", "manual"]
      # Example: Request.getUri() propagates taint (V2)
      - ["org.http4k.core", "Request", true, "getUri", "()", "", "Qualifier", "ReturnValue", "taint", "manual"]
```

### 3.3 Validate Model Syntax
```bash
# Check YAML syntax
yamllint .github/codeql/extensions/http4k/models.yml

# Or use Python
python3 -c "import yaml; yaml.safe_load(open('.github/codeql/extensions/http4k/models.yml'))"
```

## Phase 4: Analysis with Custom Models

### 4.1 Run Analysis with Models
```bash
codeql database analyze vulnerable-http4k-db \
   	--format=sarif-latest \
    --sarif-category="codeql_db" \
    --output=with-models-results.sarif \
    --model-packs .github/codeql/extensions/oscar-java/codeql-pack.yml \
    java-security-extended
```

### 4.2 Review Results with Models
```bash
# Count alerts
cat with-models-results.sarif | jq '.runs[0].results | length'

# Group by vulnerability type
cat with-models-results.sarif | jq -r '.runs[0].results[].ruleId' | sort | uniq -c

# Extract detailed results
cat with-models-results.sarif | jq '.runs[0].results[] | {rule: .ruleId, message: .message.text, location: .locations[0].physicalLocation.artifactLocation.uri}'
```

## Phase 5: Validation

### 5.1 Expected Detections Checklist

#### V1 Endpoints (9 total)
| Vulnerability | Endpoint | Expected Query | Status |
|--------------|----------|----------------|---------|
| SQL Injection | `/api/user` | `java/sql-injection` | ☐ |
| SQL Injection (lens) | `/api/profile` | `java/sql-injection` | ☐ |
| XSS (body) | `/api/echo` | `java/xss` | ☐ |
| XSS (lens) | `/api/search` | `java/xss` | ☐ |
| Path Traversal | `/api/file` | `java/path-injection` | ☐ |
| Path Traversal (URI) | `/api/download` | `java/path-injection` | ☐ |
| Header Injection | `/api/set-header` | `java/http-response-splitting` | ☐ |
| Open Redirect | `/redirect` | `java/unvalidated-url-redirection` | ☐ |
| Command Injection | `/api/ping` | `java/command-injection` | ☐ |

#### V2 Endpoints - SQL Injection (5 total)
| Vulnerability | Endpoint | Function Tested | Status |
|--------------|----------|----------------|---------|
| SQL Injection (lens get) | `/api/v2/sql/lens-get` | `LensExtractor.get()` | ☐ |
| SQL Injection (lens extract) | `/api/v2/sql/lens-extract` | `LensExtractor.extract()` | ☐ |
| SQL Injection (request header) | `/api/v2/sql/request-header` | `Request.header()` | ☐ |
| SQL Injection (URI query) | `/api/v2/sql/uri-query` | `Uri.getQuery()` | ☐ |
| SQL Injection (HttpMessage header) | `/api/v2/sql/httpmessage-header` | `HttpMessage.header()` | ☐ |

#### V2 Endpoints - XSS (4 total)
| Vulnerability | Endpoint | Function Tested | Status |
|--------------|----------|----------------|---------|
| XSS (lens injector) | `/api/v2/xss/lens-injector` | `LensInjector.inject()` | ☐ |
| XSS (HttpMessage body) | `/api/v2/xss/httpmessage-body` | `HttpMessage.body()` | ☐ |
| XSS (body stream) | `/api/v2/xss/body-stream` | `Body.getStream()` | ☐ |
| XSS (toMessage) | `/api/v2/xss/to-message` | `Response.toMessage()` | ☐ |

#### V2 Endpoints - Path Traversal (4 total)
| Vulnerability | Endpoint | Function Tested | Status |
|--------------|----------|----------------|---------|
| Path Traversal (URI path) | `/api/v2/path/uri-path` | `Request.getUri()` + `Uri.path()` | ☐ |
| Path Traversal (getPath) | `/api/v2/path/uri-getpath` | `Uri.getPath()` | ☐ |
| Path Traversal (request header) | `/api/v2/path/request-header` | `Request.header()` | ☐ |
| Path Traversal (body stream) | `/api/v2/path/body-stream` | `Body.getStream()` | ☐ |

#### V2 Endpoints - Header Injection (3 total)
| Vulnerability | Endpoint | Function Tested | Status |
|--------------|----------|----------------|---------|
| Header Injection (URI query) | `/api/v2/header/uri-query` | `Uri.getQuery()` | ☐ |
| Header Injection (lens extract) | `/api/v2/header/lens-extract` | `LensExtractor.extract()` | ☐ |
| Header Injection (body stream) | `/api/v2/header/body-stream` | `Body.getStream()` | ☐ |

#### V2 Endpoints - Open Redirect (3 total)
| Vulnerability | Endpoint | Function Tested | Status |
|--------------|----------|----------------|---------|
| Open Redirect (request header) | `/api/v2/redirect/request-header` | `Request.header()` | ☐ |
| Open Redirect (URI query) | `/api/v2/redirect/uri-query` | `Uri.getQuery()` | ☐ |
| Open Redirect (lens get) | `/api/v2/redirect/lens-get` | `LensExtractor.get()` | ☐ |

#### V2 Endpoints - Command Injection (3 total)
| Vulnerability | Endpoint | Function Tested | Status |
|--------------|----------|----------------|---------|
| Command Injection (lens get) | `/api/v2/cmd/lens-get` | `LensExtractor.get()` | ☐ |
| Command Injection (request header) | `/api/v2/cmd/request-header` | `Request.header()` | ☐ |
| Command Injection (HttpMessage header) | `/api/v2/cmd/httpmessage-header` | `HttpMessage.header()` | ☐ |

**Total Expected: 28 vulnerabilities**

### 5.2 Compare Results
```bash
# Create comparison report
python3 << 'EOF'
import json

with open('results/baseline-results.sarif') as f:
    baseline = json.load(f)
    
with open('results/with-models-results.sarif') as f:
    with_models = json.load(f)

baseline_count = len(baseline['runs'][0]['results'])
with_models_count = len(with_models['runs'][0]['results'])

print(f"Baseline alerts: {baseline_count}")
print(f"With models alerts: {with_models_count}")
print(f"New alerts: {with_models_count - baseline_count}")
print(f"\nImprovement: {((with_models_count - baseline_count) / max(1, baseline_count) * 100):.1f}%")
print(f"Expected: 28 vulnerabilities")
print(f"Coverage: {(with_models_count / 28 * 100):.1f}%")
EOF
```

## Phase 6: Debugging Models

### 6.1 If No New Alerts Appear

**Check 1: Verify models are loaded**
```bash
codeql resolve extensions --search-path=.github/codeql/extensions
```

**Check 2: Test individual query**
```bash
codeql query run \
  --database=vulnerable-http4k-db \
  --search-path=.github/codeql/extensions \
  <path-to-codeql-home>/java/ql/src/Security/CWE/CWE-089/SqlInjection.ql \
  --output=test-query-results.bqrs
  
codeql bqrs decode test-query-results.bqrs --format=text
```

**Check 3: Verify method signatures**
```bash
# Extract method signatures from database
codeql database run-queries vulnerable-http4k-db \
  --search-path=.github/codeql/extensions \
  - << 'EOF'
import java

from Method m
where m.getDeclaringType().hasQualifiedName("org.http4k.core", "Request")
select m.getName(), m.getSignature()
EOF
```

**Check 4: Test V2-specific methods**
```bash
# Verify V2 route functions are present
codeql database run-queries vulnerable-http4k-db - << 'EOF'
import java

from Method m
where m.getDeclaringType().getPackage().getName() = "com.example.routes"
  and m.getName().matches("%v2%")
select m.getName(), m.getDeclaringType().getName()
EOF
```

**Check 5: Enable verbose logging**
```bash
codeql database analyze vulnerable-http4k-db \
  codeql/java-queries:codeql-suites/java-security-and-quality.qls \
  --format=sarif-latest \
  --output=debug-results.sarif \
  --search-path=.github/codeql/extensions \
  --verbosity=debug 2>&1 | tee debug.log
```

### 6.2 If Too Many False Positives

**Add Sanitizers**:
```yaml
- addsTo:
    pack: codeql/java-all
    extensible: sanitizerModel
  data:
    - ["org.http4k.util", "Sanitizer", true, "sanitize", "(String)", "", "Argument[0]", "xss", "manual"]
```

**Refine Sink Conditions**: Make sinks more specific (e.g., only HTML responses for XSS)

### 6.3 V2-Specific Debugging

**Common V2 Issues**:
- `LensExtractor.get()` vs `LensExtractor.extract()` - different methods, both need modeling
- `Request.header()` returns nullable String - model should account for this
- `Uri.getQuery()` returns raw query string - needs parsing in vulnerable code
- `Body.getStream()` returns InputStream - taint must flow through stream operations
- `HttpMessage.header()` - ensure parent interface is modeled correctly

## Phase 7: Iteration

### 7.1 Model Refinement Process
1. Identify missing detections
2. Check if source, sink, or summary is missing
3. Verify method signatures match exactly (especially V2 methods)
4. Test with individual endpoints first (easier to debug)
5. Add/update models
6. Re-run analysis
7. Repeat until all 28 vulnerabilities detected

### 7.2 Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| No alerts | Models not loaded | Check `--search-path` |
| Wrong signature | Kotlin synthetic methods | Use `$Companion`, `$default` |
| Missing flows | Summary not defined | Add taint propagation summary |
| V2 endpoints not detected | Missing V2-specific sources | Model `LensExtractor.get()`, `Request.header()`, etc. |
| Header flows missing | Interface method not modeled | Model `HttpMessage.header()` |
| Stream flows missing | Stream taint not tracked | Add stream read as taint step |
| False negatives | Insufficient sources/sinks | Add more model entries |
| False positives | Over-broad models | Add sanitizers or refine conditions |

### 7.3 Progressive Testing Approach

Test models incrementally:
1. **Phase 1**: Original 9 endpoints (baseline functionality)
2. **Phase 2**: V2 SQL Injection (5 endpoints)
3. **Phase 3**: V2 XSS (4 endpoints)
4. **Phase 4**: V2 Path Traversal (4 endpoints)
5. **Phase 5**: V2 Header Injection (3 endpoints)
6. **Phase 6**: V2 Open Redirect (3 endpoints)
7. **Phase 7**: V2 Command Injection (3 endpoints)

## Phase 8: Documentation

### 8.1 Document Your Models
For each model entry, document:
- **Why**: Why is this a source/sink/summary?
- **Flow**: What data flow does it participate in?
- **Test**: Which endpoint in the vulnerable app tests it?
- **Version**: Original or V2 endpoint?

### 8.2 Create Model Coverage Report
```bash
# List all modeled functions
cat .github/codeql/extensions/http4k/models.yml | grep -E '^\s+- \[' | wc -l

# Count route files
echo "Original routes:"
ls -1 src/main/kotlin/com/example/routes/*.kt | grep -v "v2" | wc -l
echo "V2 routes:"
ls -1 src/main/kotlin/com/example/routes/*-v2.kt | wc -l

# Calculate coverage
python3 << 'EOF'
import json
with open('with-models-results.sarif') as f:
    results = json.load(f)
    detected = len(results['runs'][0]['results'])
    total = 28
    print(f"Coverage: {detected}/{total} ({detected/total*100:.1f}%)")
EOF
```

### 8.3 V2 Endpoint Coverage Matrix
Create a coverage matrix showing which http4k functions are tested:

| http4k Function | Original | V2 | Total Tests |
|----------------|----------|-----|-------------|
| `Request.query()` | 5 | 1 | 6 |
| `Request.header()` | 0 | 5 | 5 |
| `LensExtractor.extract()` | 2 | 2 | 4 |
| `LensExtractor.get()` | 0 | 5 | 5 |
| `Uri.getQuery()` | 0 | 4 | 4 |
| `Uri.path/getPath()` | 1 | 2 | 3 |
| `Body.getStream()` | 0 | 4 | 4 |
| `HttpMessage.header()` | 0 | 2 | 2 |
| `HttpMessage.body()` | 0 | 1 | 1 |
| `LensInjector.inject()` | 0 | 1 | 1 |
| `Response.toMessage()` | 0 | 1 | 1 |

## Success Criteria

✅ Baseline scan: 0-2 alerts (none from http4k)  
✅ With models scan: **28 alerts** (original + V2)  
✅ All vulnerability types covered  
✅ No false positives in known-good code  
✅ Models documented and version controlled

## Next Steps

1. Test models on real http4k applications
2. Contribute models to CodeQL model repository
3. Add more complex vulnerability patterns
4. Test with different http4k versions
5. Add inter-procedural flows (multi-step taint propagation)
6. Test with http4k middleware and filters