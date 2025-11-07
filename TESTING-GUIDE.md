# CodeQL Testing Guide for http4k Models

## Overview

This guide walks through the complete testing process for validating CodeQL models for the http4k library.

## Phase 1: Setup

### 1.1 Build the Application
```bash
cd vulnerable-http4k-app
./gradlew clean build
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

**Model Structure Example**:
```yaml
extensions:
  - addsTo:
      pack: codeql/java-all
      extensible: sourceModel
    data:
      # Example: Request.query() as remote source
      - ["org.http4k.core", "Request", true, "query", "(String)", "", "ReturnValue", "remote", "manual"]
      
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

**Check 4: Enable verbose logging**
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

## Phase 7: Iteration

### 7.1 Model Refinement Process
1. Identify missing detections
2. Check if source, sink, or summary is missing
3. Verify method signatures match exactly
4. Add/update models
5. Re-run analysis
6. Repeat until all vulnerabilities detected

### 7.2 Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| No alerts | Models not loaded | Check `--search-path` |
| Wrong signature | Kotlin synthetic methods | Use `$Companion`, `$default` |
| Missing flows | Summary not defined | Add taint propagation summary |
| False negatives | Insufficient sources/sinks | Add more model entries |
| False positives | Over-broad models | Add sanitizers or refine conditions |

## Phase 8: Documentation

### 8.1 Document Your Models
For each model entry, document:
- **Why**: Why is this a source/sink/summary?
- **Flow**: What data flow does it participate in?
- **Test**: Which endpoint in the vulnerable app tests it?

### 8.2 Create Model Coverage Report
```bash
# List all modeled functions
cat .github/codeql/extensions/http4k/models.yml | grep -E '^\s+- \[' | wc -l

# List tested vulnerabilities
ls -1 src/main/kotlin/com/example/routes/*.kt | wc -l
```

## Success Criteria

✅ Baseline scan: 0-2 alerts (none from http4k)  
✅ With models scan: 9+ alerts (one per vulnerability)  
✅ All vulnerability types covered  
✅ No false positives in known-good code  
✅ Models documented and version controlled

## Next Steps

1. Test models on real http4k applications
2. Contribute models to CodeQL model repository
3. Add more complex vulnerability patterns
4. Test with different http4k versions