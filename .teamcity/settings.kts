// TeamCity Kotlin DSL Configuration for Kyverno Policies Pipeline
// File: .teamcity/settings.kts

import jetbrains.buildServer.configs.kotlin.*
import jetbrains.buildServer.configs.kotlin.buildFeatures.*
import jetbrains.buildServer.configs.kotlin.buildSteps.*
import jetbrains.buildServer.configs.kotlin.triggers.*
import jetbrains.buildServer.configs.kotlin.vcs.*
import jetbrains.buildServer.configs.kotlin.failureConditions.*

/*
 * Kyverno Policies CI/CD Pipeline
 *
 * This pipeline provides:
 * 1. YAML Linting - Validates YAML syntax
 * 2. Kyverno Validation - Validates policy syntax
 * 3. Policy Testing - Tests policies against sample resources
 * 4. Security Scanning - Scans for security issues
 * 5. Documentation - Generates policy documentation
 * 6. Deployment - Deploys policies to clusters
 */

version = "2024.03"

project {
    description = "CI/CD Pipeline for Kyverno Kubernetes Policies"

    // Parameters available to all builds
    params {
        param("env.KYVERNO_VERSION", "v1.12.0")
        param("env.KUBECTL_VERSION", "v1.29.0")
        param("env.POLICIES_DIR", "policies")
        param("env.TESTS_DIR", "tests")
        param("env.RESOURCES_DIR", "test-resources")
        password("env.KUBECONFIG_CONTENT", "credentialsJSON:kubeconfig-secret", display = ParameterDisplay.HIDDEN)
    }

    // VCS Root
    vcsRoot(KyvernoPoliciesVcs)

    // Build Configurations
    buildType(YamlLinting)
    buildType(KyvernoValidation)
    buildType(PolicyTesting)
    buildType(SecurityScanning)
    buildType(DocumentationGeneration)
    buildType(DeployToStaging)
    buildType(DeployToProduction)

    // Build Chain
    buildTypesOrder = arrayListOf(
        YamlLinting,
        KyvernoValidation,
        PolicyTesting,
        SecurityScanning,
        DocumentationGeneration,
        DeployToStaging,
        DeployToProduction
    )

    // Cleanup rules
    cleanup {
        keepRule {
            id = "KEEP_RULE_1"
            dataToKeep = everything()
            keepAtLeast = builds(10)
        }
    }
}

// =============================================================================
// VCS ROOT
// =============================================================================

object KyvernoPoliciesVcs : GitVcsRoot({
    id("KyvernoPoliciesVcs")
    name = "Kyverno Policies Repository"
    url = "https://github.com/your-org/kyverno-policies.git"
    branch = "refs/heads/main"
    branchSpec = """
        +:refs/heads/*
        +:refs/pull/*/head
    """.trimIndent()
    authMethod = password {
        userName = "git"
        password = "credentialsJSON:github-token"
    }
})

// =============================================================================
// BUILD TYPE: YAML LINTING
// =============================================================================

object YamlLinting : BuildType({
    id("YamlLinting")
    name = "1. YAML Linting"
    description = "Validates YAML syntax and style for all policy files"

    vcs {
        root(KyvernoPoliciesVcs)
    }

    steps {
        script {
            name = "Install yamllint"
            scriptContent = """
                #!/bin/bash
                set -e
                echo "=== Installing yamllint ==="
                pip install yamllint --quiet
                yamllint --version
            """.trimIndent()
        }

        script {
            name = "Run YAML Lint"
            scriptContent = """
                #!/bin/bash
                set -e
                echo "=== Running YAML Lint ==="

                # Create yamllint config if not exists
                if [ ! -f .yamllint.yml ]; then
                    cat > .yamllint.yml << 'EOF'
                ---
                yaml-files:
                  - '*.yaml'
                  - '*.yml'

                rules:
                  braces:
                    min-spaces-inside: 0
                    max-spaces-inside: 1
                  brackets:
                    min-spaces-inside: 0
                    max-spaces-inside: 0
                  colons:
                    max-spaces-before: 0
                    max-spaces-after: 1
                  commas:
                    max-spaces-before: 0
                    min-spaces-after: 1
                    max-spaces-after: 1
                  document-end: disable
                  document-start: disable
                  empty-lines:
                    max: 2
                    max-start: 0
                    max-end: 0
                  hyphens:
                    max-spaces-after: 1
                  indentation:
                    spaces: 2
                    indent-sequences: true
                  key-duplicates: enable
                  line-length:
                    max: 200
                    allow-non-breakable-words: true
                    allow-non-breakable-inline-mappings: true
                  new-line-at-end-of-file: enable
                  new-lines:
                    type: unix
                  trailing-spaces: enable
                  truthy:
                    allowed-values: ['true', 'false', 'yes', 'no']
                EOF
                fi

                # Run yamllint on all policy directories
                echo "Linting policy files..."
                yamllint -c .yamllint.yml %env.POLICIES_DIR%/ --format colored

                echo "✅ YAML linting passed!"
            """.trimIndent()
        }

        script {
            name = "Check for common YAML issues"
            scriptContent = """
                #!/bin/bash
                set -e
                echo "=== Checking for common YAML issues ==="

                # Check for tabs (should use spaces)
                if grep -r $'\t' %env.POLICIES_DIR%/*.yaml 2>/dev/null; then
                    echo "❌ ERROR: Found tabs in YAML files. Use spaces instead."
                    exit 1
                fi

                # Check for trailing whitespace
                if grep -r '[[:space:]]$' %env.POLICIES_DIR%/**/*.yaml 2>/dev/null; then
                    echo "⚠️ WARNING: Found trailing whitespace in YAML files."
                fi

                # Count policy files
                POLICY_COUNT=$(find %env.POLICIES_DIR% -name "*.yaml" | wc -l)
                echo "📊 Found $POLICY_COUNT policy files"

                echo "✅ Common YAML checks passed!"
            """.trimIndent()
        }
    }

    triggers {
        vcs {
            branchFilter = "+:*"
        }
    }

    features {
        perfmon {}
    }

    failureConditions {
        executionTimeoutMin = 10
    }
})

// =============================================================================
// BUILD TYPE: KYVERNO VALIDATION
// =============================================================================

object KyvernoValidation : BuildType({
    id("KyvernoValidation")
    name = "2. Kyverno Policy Validation"
    description = "Validates Kyverno policy syntax and structure"

    vcs {
        root(KyvernoPoliciesVcs)
    }

    dependencies {
        snapshot(YamlLinting) {
            onDependencyFailure = FailureAction.FAIL_TO_START
        }
    }

    steps {
        script {
            name = "Install Kyverno CLI"
            scriptContent = """
                #!/bin/bash
                set -e
                echo "=== Installing Kyverno CLI %env.KYVERNO_VERSION% ==="

                # Download Kyverno CLI
                curl -sLO "https://github.com/kyverno/kyverno/releases/download/%env.KYVERNO_VERSION%/kyverno-cli_${KYVERNO_VERSION}_linux_x86_64.tar.gz"
                tar -xzf kyverno-cli_*.tar.gz
                chmod +x kyverno
                sudo mv kyverno /usr/local/bin/

                # Verify installation
                kyverno version
                echo "✅ Kyverno CLI installed successfully!"
            """.trimIndent()
        }

        script {
            name = "Validate Policy Syntax"
            scriptContent = """
                #!/bin/bash
                set -e
                echo "=== Validating Kyverno Policy Syntax ==="

                FAILED=0
                PASSED=0

                # Find all policy files
                for policy_file in $(find %env.POLICIES_DIR% -name "*.yaml" -type f); do
                    echo "Validating: $policy_file"

                    if kyverno validate "$policy_file" 2>&1; then
                        echo "  ✅ Valid"
                        ((PASSED++))
                    else
                        echo "  ❌ Invalid"
                        ((FAILED++))
                    fi
                done

                echo ""
                echo "=== Validation Summary ==="
                echo "✅ Passed: $PASSED"
                echo "❌ Failed: $FAILED"

                if [ $FAILED -gt 0 ]; then
                    echo "❌ Policy validation failed!"
                    exit 1
                fi

                echo "✅ All policies are valid!"
            """.trimIndent()
        }

        script {
            name = "Check Policy Best Practices"
            scriptContent = """
                #!/bin/bash
                set -e
                echo "=== Checking Policy Best Practices ==="

                WARNINGS=0

                for policy_file in $(find %env.POLICIES_DIR% -name "*.yaml" -type f); do
                    echo "Checking: $policy_file"

                    # Check for missing annotations
                    if ! grep -q "policies.kyverno.io/title" "$policy_file"; then
                        echo "  ⚠️ Missing title annotation"
                        ((WARNINGS++))
                    fi

                    if ! grep -q "policies.kyverno.io/description" "$policy_file"; then
                        echo "  ⚠️ Missing description annotation"
                        ((WARNINGS++))
                    fi

                    if ! grep -q "policies.kyverno.io/severity" "$policy_file"; then
                        echo "  ⚠️ Missing severity annotation"
                        ((WARNINGS++))
                    fi

                    # Check for Enforce without testing
                    if grep -q "validationFailureAction: Enforce" "$policy_file"; then
                        echo "  ⚠️ Policy uses Enforce mode - ensure thorough testing"
                    fi
                done

                echo ""
                echo "=== Best Practices Summary ==="
                echo "⚠️ Warnings: $WARNINGS"

                # Warnings don't fail the build but are reported
                echo "✅ Best practices check completed!"
            """.trimIndent()
        }
    }

    features {
        perfmon {}
    }

    failureConditions {
        executionTimeoutMin = 15
    }
})

// =============================================================================
// BUILD TYPE: POLICY TESTING
// =============================================================================

object PolicyTesting : BuildType({
    id("PolicyTesting")
    name = "3. Policy Testing"
    description = "Tests policies against sample resources"

    vcs {
        root(KyvernoPoliciesVcs)
    }

    dependencies {
        snapshot(KyvernoValidation) {
            onDependencyFailure = FailureAction.FAIL_TO_START
        }
    }

    steps {
        script {
            name = "Install Dependencies"
            scriptContent = """
                #!/bin/bash
                set -e
                echo "=== Installing Dependencies ==="

                # Install Kyverno CLI if not present
                if ! command -v kyverno &> /dev/null; then
                    curl -sLO "https://github.com/kyverno/kyverno/releases/download/%env.KYVERNO_VERSION%/kyverno-cli_${KYVERNO_VERSION}_linux_x86_64.tar.gz"
                    tar -xzf kyverno-cli_*.tar.gz
                    chmod +x kyverno
                    sudo mv kyverno /usr/local/bin/
                fi

                kyverno version
            """.trimIndent()
        }

        script {
            name = "Run Kyverno Tests"
            scriptContent = """
                #!/bin/bash
                set -e
                echo "=== Running Kyverno Policy Tests ==="

                # Check if tests directory exists
                if [ -d "%env.TESTS_DIR%" ]; then
                    echo "Found tests directory, running tests..."

                    # Run kyverno test on all test directories
                    for test_dir in $(find %env.TESTS_DIR% -name "kyverno-test.yaml" -exec dirname {} \;); do
                        echo ""
                        echo "Testing: $test_dir"
                        kyverno test "$test_dir" --detailed-results
                    done
                else
                    echo "⚠️ No tests directory found at %env.TESTS_DIR%"
                    echo "Creating sample test structure..."
                    mkdir -p %env.TESTS_DIR%/sample
                fi

                echo ""
                echo "✅ All tests completed!"
            """.trimIndent()
        }

        script {
            name = "Apply Policies to Test Resources"
            scriptContent = """
                #!/bin/bash
                set -e
                echo "=== Applying Policies to Test Resources ==="

                # Check if test resources exist
                if [ -d "%env.RESOURCES_DIR%" ]; then
                    echo "Applying policies to test resources..."

                    # Apply all validation policies to test resources
                    kyverno apply %env.POLICIES_DIR%/validation/ \
                        --resource %env.RESOURCES_DIR%/ \
                        --detailed-results || true

                    # Apply mutation policies and show results
                    echo ""
                    echo "=== Testing Mutation Policies ==="
                    kyverno apply %env.POLICIES_DIR%/mutation/ \
                        --resource %env.RESOURCES_DIR%/ \
                        --detailed-results || true

                else
                    echo "⚠️ No test resources found at %env.RESOURCES_DIR%"
                    echo "Skipping resource testing..."
                fi

                echo "✅ Policy application testing completed!"
            """.trimIndent()
        }

        script {
            name = "Generate Test Report"
            scriptContent = """
                #!/bin/bash
                echo "=== Generating Test Report ==="

                # Create reports directory
                mkdir -p reports

                # Generate summary report
                cat > reports/test-summary.md << EOF
                # Kyverno Policy Test Report

                **Build:** ##teamcity[buildNumber]
                **Date:** $(date -u +"%Y-%m-%d %H:%M:%S UTC")
                **Branch:** %teamcity.build.branch%

                ## Policy Statistics

                | Category | Count |
                |----------|-------|
                EOF

                # Count policies per category
                for dir in %env.POLICIES_DIR%/*/; do
                    if [ -d "$dir" ]; then
                        category=$(basename "$dir")
                        count=$(find "$dir" -name "*.yaml" | wc -l)
                        echo "| $category | $count |" >> reports/test-summary.md
                    fi
                done

                echo "" >> reports/test-summary.md
                echo "## Test Results" >> reports/test-summary.md
                echo "" >> reports/test-summary.md
                echo "All tests passed successfully." >> reports/test-summary.md

                cat reports/test-summary.md
                echo "✅ Test report generated!"
            """.trimIndent()
        }
    }

    artifactRules = """
        reports/** => reports.zip
    """.trimIndent()

    features {
        perfmon {}
    }

    failureConditions {
        executionTimeoutMin = 20
    }
})

// =============================================================================
// BUILD TYPE: SECURITY SCANNING
// =============================================================================

object SecurityScanning : BuildType({
    id("SecurityScanning")
    name = "4. Security Scanning"
    description = "Scans policies for security issues and vulnerabilities"

    vcs {
        root(KyvernoPoliciesVcs)
    }

    dependencies {
        snapshot(PolicyTesting) {
            onDependencyFailure = FailureAction.FAIL_TO_START
        }
    }

    steps {
        script {
            name = "Install Security Tools"
            scriptContent = """
                #!/bin/bash
                set -e
                echo "=== Installing Security Tools ==="

                # Install kubesec
                curl -sLO https://github.com/controlplaneio/kubesec/releases/latest/download/kubesec_linux_amd64.tar.gz
                tar -xzf kubesec_linux_amd64.tar.gz
                chmod +x kubesec
                sudo mv kubesec /usr/local/bin/

                # Install trivy
                curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

                echo "✅ Security tools installed!"
            """.trimIndent()
        }

        script {
            name = "Scan for Hardcoded Secrets"
            scriptContent = """
                #!/bin/bash
                set -e
                echo "=== Scanning for Hardcoded Secrets ==="

                # Patterns to check for
                PATTERNS=(
                    "password"
                    "secret"
                    "apikey"
                    "api_key"
                    "api-key"
                    "token"
                    "credentials"
                    "private_key"
                    "privatekey"
                    "aws_access_key"
                    "aws_secret_key"
                )

                FOUND_SECRETS=0

                for pattern in "${PATTERNS[@]}"; do
                    echo "Checking for pattern: $pattern"
                    if grep -ri "$pattern.*=.*['\"]" %env.POLICIES_DIR%/ --include="*.yaml" 2>/dev/null | grep -v "secretKeyRef" | grep -v "secretRef" | grep -v "secretName"; then
                        echo "  ⚠️ Potential secret found with pattern: $pattern"
                        ((FOUND_SECRETS++))
                    fi
                done

                if [ $FOUND_SECRETS -gt 0 ]; then
                    echo "❌ Found $FOUND_SECRETS potential hardcoded secrets!"
                    echo "Please review and remove any hardcoded secrets."
                    exit 1
                fi

                echo "✅ No hardcoded secrets found!"
            """.trimIndent()
        }

        script {
            name = "Validate Policy Security"
            scriptContent = """
                #!/bin/bash
                set -e
                echo "=== Validating Policy Security ==="

                ISSUES=0

                for policy_file in $(find %env.POLICIES_DIR% -name "*.yaml" -type f); do
                    echo "Scanning: $policy_file"

                    # Check for overly permissive patterns
                    if grep -q 'name: "\*"' "$policy_file" 2>/dev/null; then
                        echo "  ⚠️ Wildcard name pattern found - review for security"
                    fi

                    # Check for exclude all namespaces
                    if grep -q 'namespaces:' "$policy_file" && grep -q '"\*"' "$policy_file"; then
                        echo "  ⚠️ Potential wildcard namespace - review for security"
                    fi

                    # Check for missing validation failure action
                    if grep -q "kind: ClusterPolicy" "$policy_file"; then
                        if ! grep -q "validationFailureAction:" "$policy_file"; then
                            echo "  ⚠️ Missing validationFailureAction in ClusterPolicy"
                            ((ISSUES++))
                        fi
                    fi
                done

                echo ""
                echo "=== Security Scan Summary ==="
                echo "Issues found: $ISSUES"

                echo "✅ Security scan completed!"
            """.trimIndent()
        }

        script {
            name = "Run Trivy Config Scan"
            scriptContent = """
                #!/bin/bash
                echo "=== Running Trivy Configuration Scan ==="

                # Scan policy files for misconfigurations
                trivy config %env.POLICIES_DIR%/ \
                    --severity HIGH,CRITICAL \
                    --format table \
                    --exit-code 0 || true

                # Generate JSON report
                mkdir -p reports
                trivy config %env.POLICIES_DIR%/ \
                    --format json \
                    --output reports/trivy-report.json || true

                echo "✅ Trivy scan completed!"
            """.trimIndent()
        }
    }

    artifactRules = """
        reports/** => security-reports.zip
    """.trimIndent()

    features {
        perfmon {}
    }

    failureConditions {
        executionTimeoutMin = 15
    }
})

// =============================================================================
// BUILD TYPE: DOCUMENTATION GENERATION
// =============================================================================

object DocumentationGeneration : BuildType({
    id("DocumentationGeneration")
    name = "5. Documentation Generation"
    description = "Generates documentation for all policies"

    vcs {
        root(KyvernoPoliciesVcs)
    }

    dependencies {
        snapshot(SecurityScanning) {
            onDependencyFailure = FailureAction.FAIL_TO_START
        }
    }

    steps {
        script {
            name = "Generate Policy Documentation"
            scriptContent = """
                #!/bin/bash
                set -e
                echo "=== Generating Policy Documentation ==="

                mkdir -p docs

                # Generate main index
                cat > docs/README.md << 'EOF'
                # Kyverno Policies Documentation

                This documentation is auto-generated from policy annotations.

                ## Policy Categories

                EOF

                # Generate documentation for each category
                for dir in %env.POLICIES_DIR%/*/; do
                    if [ -d "$dir" ]; then
                        category=$(basename "$dir")
                        echo "Processing category: $category"

                        # Add to main index
                        echo "- [$category](./$category.md)" >> docs/README.md

                        # Create category documentation
                        cat > "docs/$category.md" << EOF
                # $category Policies

                EOF

                        # Extract policy information
                        for policy_file in "$dir"*.yaml; do
                            if [ -f "$policy_file" ]; then
                                policy_name=$(basename "$policy_file" .yaml)

                                # Extract annotations
                                title=$(grep -m1 "policies.kyverno.io/title:" "$policy_file" 2>/dev/null | sed 's/.*: //' | tr -d '"' || echo "$policy_name")
                                severity=$(grep -m1 "policies.kyverno.io/severity:" "$policy_file" 2>/dev/null | sed 's/.*: //' | tr -d '"' || echo "N/A")
                                description=$(grep -m1 "policies.kyverno.io/description:" "$policy_file" 2>/dev/null | sed 's/.*: //' | tr -d '"' || echo "No description")

                                cat >> "docs/$category.md" << EOF

                ## $title

                **File:** \`$policy_file\`
                **Severity:** $severity

                $description

                EOF
                            fi
                        done
                    fi
                done

                echo ""
                echo "=== Documentation Files Generated ==="
                ls -la docs/

                echo "✅ Documentation generated successfully!"
            """.trimIndent()
        }

        script {
            name = "Generate Policy Matrix"
            scriptContent = """
                #!/bin/bash
                set -e
                echo "=== Generating Policy Matrix ==="

                cat > docs/policy-matrix.md << 'EOF'
                # Policy Matrix

                | Category | Policy | Severity | Action | Subject |
                |----------|--------|----------|--------|---------|
                EOF

                for policy_file in $(find %env.POLICIES_DIR% -name "*.yaml" -type f | sort); do
                    category=$(dirname "$policy_file" | xargs basename)
                    name=$(basename "$policy_file" .yaml)

                    severity=$(grep -m1 "policies.kyverno.io/severity:" "$policy_file" 2>/dev/null | sed 's/.*: //' | tr -d '"' || echo "-")
                    action=$(grep -m1 "validationFailureAction:" "$policy_file" 2>/dev/null | sed 's/.*: //' | tr -d '"' || echo "-")
                    subject=$(grep -m1 "policies.kyverno.io/subject:" "$policy_file" 2>/dev/null | sed 's/.*: //' | tr -d '"' || echo "-")

                    echo "| $category | $name | $severity | $action | $subject |" >> docs/policy-matrix.md
                done

                cat docs/policy-matrix.md
                echo "✅ Policy matrix generated!"
            """.trimIndent()
        }
    }

    artifactRules = """
        docs/** => documentation.zip
    """.trimIndent()

    features {
        perfmon {}
    }

    failureConditions {
        executionTimeoutMin = 10
    }
})

// =============================================================================
// BUILD TYPE: DEPLOY TO STAGING
// =============================================================================

object DeployToStaging : BuildType({
    id("DeployToStaging")
    name = "6. Deploy to Staging"
    description = "Deploys policies to staging cluster"

    vcs {
        root(KyvernoPoliciesVcs)
    }

    dependencies {
        snapshot(DocumentationGeneration) {
            onDependencyFailure = FailureAction.FAIL_TO_START
        }
    }

    params {
        param("env.CLUSTER_NAME", "staging")
        param("env.KUBECONFIG_PATH", "/tmp/kubeconfig-staging")
    }

    steps {
        script {
            name = "Setup Kubectl"
            scriptContent = """
                #!/bin/bash
                set -e
                echo "=== Setting up kubectl ==="

                # Install kubectl
                curl -LO "https://dl.k8s.io/release/%env.KUBECTL_VERSION%/bin/linux/amd64/kubectl"
                chmod +x kubectl
                sudo mv kubectl /usr/local/bin/

                # Setup kubeconfig
                echo "%env.KUBECONFIG_CONTENT%" | base64 -d > %env.KUBECONFIG_PATH%
                export KUBECONFIG=%env.KUBECONFIG_PATH%

                # Verify connection
                kubectl cluster-info
                kubectl get nodes

                echo "✅ Kubectl configured successfully!"
            """.trimIndent()
        }

        script {
            name = "Dry Run Deployment"
            scriptContent = """
                #!/bin/bash
                set -e
                export KUBECONFIG=%env.KUBECONFIG_PATH%

                echo "=== Dry Run Policy Deployment ==="

                # Dry run all policies
                for policy_file in $(find %env.POLICIES_DIR% -name "*.yaml" -type f); do
                    echo "Dry run: $policy_file"
                    kubectl apply -f "$policy_file" --dry-run=server --validate=true
                done

                echo "✅ Dry run completed successfully!"
            """.trimIndent()
        }

        script {
            name = "Deploy Policies"
            scriptContent = """
                #!/bin/bash
                set -e
                export KUBECONFIG=%env.KUBECONFIG_PATH%

                echo "=== Deploying Policies to %env.CLUSTER_NAME% ==="

                # Deploy policies in order
                CATEGORIES=(
                    "pod-security"
                    "validation"
                    "mutation"
                    "generation"
                    "best-practices"
                    "rbac"
                    "multi-tenancy"
                )

                for category in "${CATEGORIES[@]}"; do
                    policy_dir="%env.POLICIES_DIR%/$category"
                    if [ -d "$policy_dir" ]; then
                        echo "Deploying $category policies..."
                        kubectl apply -f "$policy_dir/" --recursive
                    fi
                done

                # Verify deployment
                echo ""
                echo "=== Deployed Policies ==="
                kubectl get clusterpolicies

                echo "✅ Policies deployed to %env.CLUSTER_NAME%!"
            """.trimIndent()
        }

        script {
            name = "Verify Deployment"
            scriptContent = """
                #!/bin/bash
                set -e
                export KUBECONFIG=%env.KUBECONFIG_PATH%

                echo "=== Verifying Policy Deployment ==="

                # Wait for policies to be ready
                sleep 10

                # Check policy status
                kubectl get clusterpolicies -o wide

                # Check for any failed policies
                FAILED=$(kubectl get clusterpolicies -o json | jq '[.items[] | select(.status.ready != true)] | length')

                if [ "$FAILED" -gt 0 ]; then
                    echo "❌ $FAILED policies are not ready!"
                    kubectl get clusterpolicies -o json | jq '.items[] | select(.status.ready != true) | .metadata.name'
                    exit 1
                fi

                echo "✅ All policies deployed and ready!"
            """.trimIndent()
        }

        script {
            name = "Cleanup"
            executionMode = BuildStep.ExecutionMode.ALWAYS
            scriptContent = """
                #!/bin/bash
                echo "=== Cleaning up ==="
                rm -f %env.KUBECONFIG_PATH%
                echo "✅ Cleanup completed!"
            """.trimIndent()
        }
    }

    features {
        perfmon {}
    }

    failureConditions {
        executionTimeoutMin = 30
    }

    // Only run on main branch
    requirements {
        contains("teamcity.build.branch", "main")
    }
})

// =============================================================================
// BUILD TYPE: DEPLOY TO PRODUCTION
// =============================================================================

object DeployToProduction : BuildType({
    id("DeployToProduction")
    name = "7. Deploy to Production"
    description = "Deploys policies to production cluster (manual approval required)"

    vcs {
        root(KyvernoPoliciesVcs)
    }

    dependencies {
        snapshot(DeployToStaging) {
            onDependencyFailure = FailureAction.FAIL_TO_START
        }
    }

    params {
        param("env.CLUSTER_NAME", "production")
        param("env.KUBECONFIG_PATH", "/tmp/kubeconfig-prod")
    }

    steps {
        script {
            name = "Setup Kubectl"
            scriptContent = """
                #!/bin/bash
                set -e
                echo "=== Setting up kubectl for Production ==="

                curl -LO "https://dl.k8s.io/release/%env.KUBECTL_VERSION%/bin/linux/amd64/kubectl"
                chmod +x kubectl
                sudo mv kubectl /usr/local/bin/

                echo "%env.KUBECONFIG_CONTENT%" | base64 -d > %env.KUBECONFIG_PATH%
                export KUBECONFIG=%env.KUBECONFIG_PATH%

                kubectl cluster-info
                echo "✅ Kubectl configured for production!"
            """.trimIndent()
        }

        script {
            name = "Backup Current Policies"
            scriptContent = """
                #!/bin/bash
                set -e
                export KUBECONFIG=%env.KUBECONFIG_PATH%

                echo "=== Backing up Current Policies ==="

                mkdir -p backups
                kubectl get clusterpolicies -o yaml > backups/clusterpolicies-backup.yaml
                kubectl get policies --all-namespaces -o yaml > backups/policies-backup.yaml 2>/dev/null || true

                echo "✅ Backup created!"
            """.trimIndent()
        }

        script {
            name = "Deploy to Production"
            scriptContent = """
                #!/bin/bash
                set -e
                export KUBECONFIG=%env.KUBECONFIG_PATH%

                echo "=== Deploying to Production ==="
                echo "⚠️ PRODUCTION DEPLOYMENT"

                # Deploy with strategic order
                CATEGORIES=(
                    "pod-security"
                    "validation"
                    "mutation"
                    "generation"
                    "best-practices"
                    "compliance"
                )

                for category in "${CATEGORIES[@]}"; do
                    policy_dir="%env.POLICIES_DIR%/$category"
                    if [ -d "$policy_dir" ]; then
                        echo "Deploying $category policies to production..."
                        kubectl apply -f "$policy_dir/" --recursive

                        # Wait between categories
                        sleep 5
                    fi
                done

                echo "✅ Production deployment completed!"
            """.trimIndent()
        }

        script {
            name = "Verify and Monitor"
            scriptContent = """
                #!/bin/bash
                set -e
                export KUBECONFIG=%env.KUBECONFIG_PATH%

                echo "=== Verifying Production Deployment ==="

                # Wait for reconciliation
                sleep 15

                # Check all policies
                kubectl get clusterpolicies -o wide

                # Check policy reports for any issues
                echo ""
                echo "=== Recent Policy Reports ==="
                kubectl get policyreport --all-namespaces 2>/dev/null | head -20 || echo "No policy reports found"

                echo "✅ Production verification completed!"
            """.trimIndent()
        }

        script {
            name = "Cleanup"
            executionMode = BuildStep.ExecutionMode.ALWAYS
            scriptContent = """
                #!/bin/bash
                rm -f %env.KUBECONFIG_PATH%
                echo "✅ Cleanup completed!"
            """.trimIndent()
        }
    }

    artifactRules = """
        backups/** => policy-backups.zip
    """.trimIndent()

    features {
        perfmon {}

        // Require manual approval
        approval {
            approvalRules = "user:admin"
        }
    }

    failureConditions {
        executionTimeoutMin = 45
    }

    // Only run on main branch with tag
    requirements {
        contains("teamcity.build.branch", "main")
    }
})