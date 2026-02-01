# devops-policies-kyverno — Conftest Rules

![Kyverno](https://img.shields.io/badge/Kyverno-v1%20%7C%20v2-326CE5?logo=kubernetes&logoColor=white)
![OPA](https://img.shields.io/badge/OPA-Rego%20v1-7D9199?logo=openpolicyagent&logoColor=white)
![Conftest](https://img.shields.io/badge/Conftest-compatible-5B21B6?logo=openpolicyagent&logoColor=white)
![Rules](https://img.shields.io/badge/Rules-91-22C55E?logo=checkmarx&logoColor=white)
![Deny](https://img.shields.io/badge/Deny-38-EF4444?logo=shieldsdotio&logoColor=white)
![Warn](https://img.shields.io/badge/Warn-53-F59E0B?logo=shieldsdotio&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue?logo=opensourceinitiative&logoColor=white)

A comprehensive set of OPA/Rego policies for validating your Kyverno `ClusterPolicy` and `Policy` definitions against best practices. Run these with [conftest](https://www.conftest.dev/) in your CI/CD pipeline or locally.

---

## 🚀 Quick Start

```bash
# Install conftest (if not already installed)
# macOS
brew install conftest
# Linux
wget https://github.com/open-policy-agent/conftest/releases/latest/download/conftest_Linux_x86_64.tar.gz
tar xzf conftest_Linux_x86_64.tar.gz
sudo mv conftest /usr/local/bin/

# Validate a single policy
conftest test my-policy.yaml -p policy/

# Validate all policies in a directory
conftest test policies/ -p policy/

# Output as JSON (for CI pipelines)
conftest test my-policy.yaml -p policy/ -o json

# Show only failures (no warnings)
conftest test my-policy.yaml -p policy/ --no-warn
```

---

## 📂 Rule Categories

| File | Prefix | Description | Rules |
|---|---|---|---|
| ![Metadata](https://img.shields.io/badge/-metadata.rego-6366F1?logo=files&logoColor=white) | `METADATA-*` `ANNOTATION-*` `LABEL-*` | Names, annotations, labels | ![16](https://img.shields.io/badge/16-grey) |
| ![Spec](https://img.shields.io/badge/-spec.rego-8B5CF6?logo=files&logoColor=white) | `SPEC-*` | Spec-level fields (background, failurePolicy, timeouts) | ![16](https://img.shields.io/badge/16-grey) |
| ![Rules](https://img.shields.io/badge/-rules.rego-A855F7?logo=files&logoColor=white) | `RULE-*` | Per-rule checks (match, exclude, validate, mutate, generate) | ![29](https://img.shields.io/badge/29-grey) |
| ![Security](https://img.shields.io/badge/-security.rego-EF4444?logo=files&logoColor=white) | `SECURITY-*` | Security posture (enforce vs audit, failure handling) | ![13](https://img.shields.io/badge/13-grey) |
| ![Operations](https://img.shields.io/badge/-operations.rego-F59E0B?logo=files&logoColor=white) | `PERF-*` `OPS-*` | Performance, operational hygiene, image verification | ![17](https://img.shields.io/badge/17-grey) |

---

## 📖 Rule Reference

### ![Deny](https://img.shields.io/badge/DENY-38_rules-EF4444?style=flat-square) Hard Failures

These produce hard failures and indicate definite issues:

#### ![Metadata](https://img.shields.io/badge/-Metadata-6366F1?style=flat-square&logo=tag&logoColor=white)

| Code | Summary |
|---|---|
| `METADATA-001` | Policy must have `metadata.name` |
| `METADATA-002` | Name must be DNS-compatible (lowercase, hyphens) |
| `METADATA-003` | Name must not exceed 63 characters |

#### ![Annotations](https://img.shields.io/badge/-Annotations-6366F1?style=flat-square&logo=bookmarks&logoColor=white)

| Code | Summary |
|---|---|
| `ANNOTATION-001` | Missing `policies.kyverno.io/title` |
| `ANNOTATION-002` | Missing `policies.kyverno.io/category` |
| `ANNOTATION-003` | Missing `policies.kyverno.io/severity` |
| `ANNOTATION-004` | Invalid severity value |
| `ANNOTATION-005` | Missing `policies.kyverno.io/subject` |
| `ANNOTATION-006` | Missing `policies.kyverno.io/description` |
| `ANNOTATION-007` | Empty description |
| `ANNOTATION-012` | Empty title |

#### ![Spec](https://img.shields.io/badge/-Spec-8B5CF6?style=flat-square&logo=slickpic&logoColor=white)

| Code | Summary |
|---|---|
| `SPEC-001` | No rules defined |
| `SPEC-004` | Invalid `failurePolicy` value |
| `SPEC-006` | `webhookTimeoutSeconds` out of range |
| `SPEC-010` | Invalid `validationFailureAction` value |
| `SPEC-013` | Invalid `applyRules` value |
| `SPEC-014` | ClusterPolicy should not have namespace |

#### ![Rules](https://img.shields.io/badge/-Rules-A855F7?style=flat-square&logo=targetbrand&logoColor=white)

| Code | Summary |
|---|---|
| `RULE-001` | Rule missing name |
| `RULE-004` | Duplicate rule names |
| `RULE-MATCH-001` | Rule missing match block |
| `RULE-MATCH-002` | Match block has no resource targeting |
| `RULE-MATCH-003` | Empty `resources.kinds` in match |
| `RULE-VALIDATE-001` | Validate rule missing message |
| `RULE-VALIDATE-002` | Empty validate message |
| `RULE-VALIDATE-004` | No validation method specified |
| `RULE-VALIDATE-006` | Invalid `failureAction` value |
| `RULE-MUTATE-001` | No mutation method specified |
| `RULE-GENERATE-001` | No generation source specified |
| `RULE-GENERATE-002` | Generate missing target kind |
| `RULE-CONTEXT-002` | Context entry missing name |
| `RULE-FOREACH-001` | Foreach missing list field |

#### ![Security](https://img.shields.io/badge/-Security-EF4444?style=flat-square&logo=shieldcheck&logoColor=white)

| Code | Summary |
|---|---|
| `SECURITY-004` | `failurePolicy=Ignore` with high/critical severity |
| `SECURITY-009` | Policy matches its own CRD type (recursion risk) |

#### ![Operations](https://img.shields.io/badge/-Operations-F59E0B?style=flat-square&logo=gear&logoColor=white)

| Code | Summary |
|---|---|
| `OPS-007` | Rule has no action (validate/mutate/generate/verifyImages) |
| `OPS-009` | verifyImages entry missing imageReferences |

---

### ![Warn](https://img.shields.io/badge/WARN-53_rules-F59E0B?style=flat-square) Recommendations

These are recommendations and best-practice suggestions:

#### ![Annotations](https://img.shields.io/badge/-Annotations-6366F1?style=flat-square&logo=bookmarks&logoColor=white)

| Code | Summary |
|---|---|
| `ANNOTATION-008` | Short description (< 20 chars) |
| `ANNOTATION-009` | Missing `kyverno.io/kyverno-version` |
| `ANNOTATION-010` | Missing `kyverno.io/kubernetes-version` |
| `ANNOTATION-011` | Missing `policies.kyverno.io/minversion` |
| `LABEL-001` | No labels set |

#### ![Spec](https://img.shields.io/badge/-Spec-8B5CF6?style=flat-square&logo=slickpic&logoColor=white)

| Code | Summary |
|---|---|
| `SPEC-002` | `spec.background` not explicitly set |
| `SPEC-003` | `spec.failurePolicy` not explicitly set |
| `SPEC-005` | Many rules but no `webhookTimeoutSeconds` |
| `SPEC-007` | Very low `webhookTimeoutSeconds` |
| `SPEC-008` | Deprecated `spec.validationFailureAction` |
| `SPEC-009` | Deprecated `spec.validationFailureActionOverrides` |
| `SPEC-011` | Security policy in Audit mode |
| `SPEC-012` | Too many rules (> 10), consider splitting |
| `SPEC-015` | Namespaced Policy without explicit namespace |

#### ![Rules](https://img.shields.io/badge/-Rules-A855F7?style=flat-square&logo=targetbrand&logoColor=white)

| Code | Summary |
|---|---|
| `RULE-002` | Very short rule name |
| `RULE-003` | Rule name contains whitespace |
| `RULE-MATCH-004` | Wildcard kind match (`*`) |
| `RULE-EXCLUDE-001` | Broad ClusterPolicy without system namespace exclusions |
| `RULE-EXCLUDE-002` | Empty exclude block |
| `RULE-VALIDATE-003` | Very short validate message |
| `RULE-VALIDATE-005` | No `failureAction` set at any level |
| `RULE-MUTATE-002` | Mutate + validate in same rule |
| `RULE-GENERATE-003` | `synchronize=true` implications |
| `RULE-PRECONDITION-001` | `deny` without preconditions |
| `RULE-PRECONDITION-002` | Legacy preconditions format |
| `RULE-CONTEXT-001` | Context variable name with whitespace |
| `RULE-CONTEXT-003` | ConfigMap context without namespace |

#### ![Security](https://img.shields.io/badge/-Security-EF4444?style=flat-square&logo=shieldcheck&logoColor=white)

| Code | Summary |
|---|---|
| `SECURITY-001` | High severity + Audit mode (spec level) |
| `SECURITY-002` | High severity + Audit mode (rule level) |
| `SECURITY-003` | `failurePolicy=Ignore` |
| `SECURITY-005` | Security policy with background=false |
| `SECURITY-006` | background=false without admission variables |
| `SECURITY-007` | Wildcard-only validate pattern |
| `SECURITY-008` | Not excluding kyverno namespace for Pod matches |
| `SECURITY-010` | Generating RBAC resources |
| `SECURITY-011` | Generating NetworkPolicy without sync |
| `SECURITY-012` | Mutating securityContext |

#### ![Performance](https://img.shields.io/badge/-Performance-F59E0B?style=flat-square&logo=speedtest&logoColor=white)

| Code | Summary |
|---|---|
| `PERF-001` | Matching > 5 kinds in one entry |
| `PERF-002` | Using apiCall context |
| `PERF-003` | Using imageRegistry context |
| `PERF-004` | Multiple API calls in one rule |
| `PERF-005` | Nested foreach loops |

#### ![Operations](https://img.shields.io/badge/-Operations-F59E0B?style=flat-square&logo=gear&logoColor=white)

| Code | Summary |
|---|---|
| `OPS-001` | Using v2beta1 API version |
| `OPS-002` | Legacy match.resources format |
| `OPS-003` | No operations specified in match |
| `OPS-004` | Empty namespaceSelector |
| `OPS-005` | Mutate + generate in same policy |
| `OPS-006` | Mutate + validate in same policy |
| `OPS-008` | verifyImages without attestors |
| `OPS-010` | Deprecated autogen annotation |
| `OPS-011` | Matching Secrets without operation filter |
| `OPS-012` | Matching ConfigMaps without operation filter |

---

## 🔌 CI/CD Integration

### ![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-2088FF?style=flat-square&logo=githubactions&logoColor=white)

```yaml
- name: Validate Kyverno policies
  run: |
    conftest test kyverno-policies/ -p conftest-policy/ --no-color
```

### ![GitLab CI](https://img.shields.io/badge/GitLab_CI-FC6D26?style=flat-square&logo=gitlab&logoColor=white)

```yaml
validate-kyverno:
  image: openpolicyagent/conftest:latest
  script:
    - conftest test kyverno-policies/ -p conftest-policy/
```

### ![Pre-commit](https://img.shields.io/badge/Pre--commit-FAB040?style=flat-square&logo=precommit&logoColor=black)

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/open-policy-agent/conftest
    hooks:
      - id: conftest
        args: [test, --policy, conftest-policy/]
        files: \.ya?ml$
```

---

## ⚙️ Customization

To disable specific rules, you can use conftest's `--namespace` flag to run only specific packages, or add exception logic within the Rego files using `data.exceptions` patterns.

To change a `warn` to a `deny` (or vice versa), simply edit the rule head in the corresponding `.rego` file.

---

<p align="center">
  <img src="https://img.shields.io/badge/Made_for-Kyverno-326CE5?style=for-the-badge&logo=kubernetes&logoColor=white" />
  <img src="https://img.shields.io/badge/Powered_by-OPA%2FRego-7D9199?style=for-the-badge&logo=openpolicyagent&logoColor=white" />
  <img src="https://img.shields.io/badge/Runs_with-Conftest-5B21B6?style=for-the-badge&logo=openpolicyagent&logoColor=white" />
</p>
