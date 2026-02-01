# METADATA
# title: Kyverno Policy Security Best Practices
# description: Security-focused checks for Kyverno policy definitions
# related_resources:
#   - https://kyverno.io/docs/policy-types/cluster-policy/
# authors:
#   - conftest-kyverno-linter

package main

import rego.v1

# ============================================================================
# SECURITY: ENFORCE vs AUDIT
# ============================================================================

# RULE: High or critical severity policies should use Enforce
warn contains msg if {
	is_policy
	sev := annotations["policies.kyverno.io/severity"]
	sev in {"high", "critical"}
	has_field_sec(spec, "validationFailureAction")
	lower(spec.validationFailureAction) == "audit"
	msg := sprintf("SECURITY-001: Policy '%s' has severity '%s' but validationFailureAction is 'Audit'. High/critical severity policies should use 'Enforce' in production.", [input.metadata.name, sev])
}

# RULE: Same check at per-rule level
warn contains msg if {
	is_policy
	sev := annotations["policies.kyverno.io/severity"]
	sev in {"high", "critical"}
	some rule in rules
	rule.validate
	fa := object.get(rule.validate, "failureAction", "")
	lower(fa) == "audit"
	msg := sprintf("SECURITY-002: Policy '%s', rule '%s' has severity '%s' but validate.failureAction is 'Audit'. Consider using 'Enforce' for high/critical severity.", [input.metadata.name, rule.name, sev])
}

# ============================================================================
# SECURITY: FAILURE POLICY
# ============================================================================

# RULE: failurePolicy=Ignore can silently skip policies on webhook errors
warn contains msg if {
	is_policy
	spec.failurePolicy == "Ignore"
	msg := sprintf("SECURITY-003: Policy '%s' has spec.failurePolicy=Ignore. Webhook errors will silently allow resources through without policy evaluation. Use 'Fail' for security-critical policies.", [input.metadata.name])
}

# RULE: failurePolicy=Ignore combined with high severity is dangerous
deny contains msg if {
	is_policy
	spec.failurePolicy == "Ignore"
	sev := annotations["policies.kyverno.io/severity"]
	sev in {"high", "critical"}
	msg := sprintf("SECURITY-004: Policy '%s' has failurePolicy=Ignore with severity='%s'. This is dangerous: webhook failures will bypass critical security checks.", [input.metadata.name, sev])
}

# ============================================================================
# SECURITY: BACKGROUND SCANNING
# ============================================================================

# RULE: Security policies should have background scanning enabled
warn contains msg if {
	is_policy
	has_field_sec(spec, "background")
	spec.background == false
	category := object.get(annotations, "policies.kyverno.io/category", "")
	contains(lower(category), "security")
	msg := sprintf("SECURITY-005: Policy '%s' is a security policy with background=false. Existing non-compliant resources will not be detected. Enable background scanning for visibility.", [input.metadata.name])
}

# RULE: Background=false with no admission variables is likely unintentional
warn contains msg if {
	is_policy
	has_field_sec(spec, "background")
	spec.background == false
	some rule in rules
	not rule_uses_admission_variables(rule)
	msg := sprintf("SECURITY-006: Policy '%s', rule '%s' has background=false but does not appear to use admission-request variables. background=false may be unintentional.", [input.metadata.name, rule.name])
}

# ============================================================================
# SECURITY: OVERLY PERMISSIVE PATTERNS
# ============================================================================

# RULE: Warn if a validate rule uses a wildcard pattern that accepts anything
warn contains msg if {
	is_policy
	some rule in rules
	rule.validate
	validate := rule.validate
	validate.pattern
	pattern := validate.pattern
	pattern == "*"
	msg := sprintf("SECURITY-007: Policy '%s', rule '%s' has a wildcard-only pattern ('*') which matches everything. This validation has no effect.", [input.metadata.name, rule.name])
}

# RULE: ClusterPolicy matching Pods without excluding kyverno namespace
warn contains msg if {
	is_policy
	input.kind == "ClusterPolicy"
	some rule in rules
	rule.match
	not excludes_namespace(rule, "kyverno")
	matches_kind(rule, "Pod")
	msg := sprintf("SECURITY-008: ClusterPolicy '%s', rule '%s' matches Pods but does not exclude the 'kyverno' namespace. This could interfere with Kyverno's own operation.", [input.metadata.name, rule.name])
}

# RULE: Policies should not match their own CRDs to avoid loops
deny contains msg if {
	is_policy
	some rule in rules
	rule.match
	matches_kind(rule, "ClusterPolicy")
	msg := sprintf("SECURITY-009: Policy '%s', rule '%s' matches ClusterPolicy resources. This can cause recursive loops and should be avoided.", [input.metadata.name, rule.name])
}

deny contains msg if {
	is_policy
	some rule in rules
	rule.match
	matches_kind(rule, "Policy")
	msg := sprintf("SECURITY-009: Policy '%s', rule '%s' matches Policy resources. This can cause recursive loops and should be avoided.", [input.metadata.name, rule.name])
}

# ============================================================================
# SECURITY: GENERATE RULE CONCERNS
# ============================================================================

# RULE: Generate rules creating Roles/ClusterRoles should be reviewed
warn contains msg if {
	is_policy
	some rule in rules
	has_field_sec(rule, "generate")
	gen := rule.generate
	gen.kind in {"Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"}
	msg := sprintf("SECURITY-010: Policy '%s', rule '%s' generates RBAC resource '%s'. Ensure the generated RBAC follows least-privilege principles.", [input.metadata.name, rule.name, gen.kind])
}

# RULE: Generate rules creating NetworkPolicies should be reviewed
warn contains msg if {
	is_policy
	some rule in rules
	has_field_sec(rule, "generate")
	gen := rule.generate
	gen.kind == "NetworkPolicy"
	gen.synchronize != true
	msg := sprintf("SECURITY-011: Policy '%s', rule '%s' generates a NetworkPolicy without synchronize=true. If the NetworkPolicy is deleted manually, it will not be recreated until the trigger fires again.", [input.metadata.name, rule.name])
}

# ============================================================================
# SECURITY: MUTATION CONCERNS
# ============================================================================

# RULE: Mutate rules that add security context should be reviewed
warn contains msg if {
	is_policy
	some rule in rules
	has_field_sec(rule, "mutate")
	mutate := rule.mutate
	has_field_sec(mutate, "patchStrategicMerge")
	psm := mutate.patchStrategicMerge
	has_field_sec(object.get(psm, "spec", {}), "securityContext")
	msg := sprintf("SECURITY-012: Policy '%s', rule '%s' mutates spec.securityContext. Ensure the mutation tightens security rather than loosening it.", [input.metadata.name, rule.name])
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

has_field_sec(obj, key) if {
	_ := obj[key]
}

# Check if a rule matches a specific kind
matches_kind(rule, kind) if {
	some item in object.get(rule.match, "any", [])
	resources := object.get(item, "resources", {})
	kinds := object.get(resources, "kinds", [])
	some k in kinds
	k == kind
}

matches_kind(rule, kind) if {
	some item in object.get(rule.match, "all", [])
	resources := object.get(item, "resources", {})
	kinds := object.get(resources, "kinds", [])
	some k in kinds
	k == kind
}

matches_kind(rule, kind) if {
	resources := object.get(rule.match, "resources", {})
	kinds := object.get(resources, "kinds", [])
	some k in kinds
	k == kind
}

# Check if a rule excludes a specific namespace
excludes_namespace(rule, ns) if {
	some item in object.get(rule.exclude, "any", [])
	resources := object.get(item, "resources", {})
	namespaces := object.get(resources, "namespaces", [])
	some n in namespaces
	n == ns
}

excludes_namespace(rule, ns) if {
	some item in object.get(rule.exclude, "all", [])
	resources := object.get(item, "resources", {})
	namespaces := object.get(resources, "namespaces", [])
	some n in namespaces
	n == ns
}

excludes_namespace(rule, ns) if {
	resources := object.get(rule.exclude, "resources", {})
	namespaces := object.get(resources, "namespaces", [])
	some n in namespaces
	n == ns
}

# Heuristic: does the rule reference admission-only variables
rule_uses_admission_variables(rule) if {
	walk(rule, [_, value])
	is_string(value)
	contains(value, "request.userInfo")
}

rule_uses_admission_variables(rule) if {
	walk(rule, [_, value])
	is_string(value)
	contains(value, "request.operation")
}

rule_uses_admission_variables(rule) if {
	walk(rule, [_, value])
	is_string(value)
	contains(value, "request.dryRun")
}

rule_uses_admission_variables(rule) if {
	walk(rule, [_, value])
	is_string(value)
	contains(value, "request.roles")
}

rule_uses_admission_variables(rule) if {
	walk(rule, [_, value])
	is_string(value)
	contains(value, "request.clusterRoles")
}
