# METADATA
# title: Kyverno Policy Spec Best Practices
# description: Validates spec-level fields on Kyverno policies
# related_resources:
#   - https://kyverno.io/docs/policy-types/cluster-policy/
# authors:
#   - conftest-kyverno-linter

package main

import rego.v1

# ============================================================================
# SPEC-LEVEL FIELDS
# ============================================================================

spec := object.get(input, "spec", {})

# RULE: Policy must have at least one rule
deny contains msg if {
	is_policy
	rules := object.get(spec, "rules", [])
	count(rules) == 0
	msg := sprintf("SPEC-001: Policy '%s' has no rules defined in spec.rules. A policy must contain at least one rule.", [input.metadata.name])
}

# RULE: spec.background should be explicitly set
warn contains msg if {
	is_policy
	not has_field(spec, "background")
	msg := sprintf("SPEC-002: Policy '%s' does not explicitly set spec.background. Default is 'true'. Set it explicitly for clarity, and set to 'false' if the rule uses admission-request-only variables (e.g., request.userInfo).", [input.metadata.name])
}

# RULE: spec.failurePolicy should be explicitly set
warn contains msg if {
	is_policy
	not has_field(spec, "failurePolicy")
	msg := sprintf("SPEC-003: Policy '%s' does not explicitly set spec.failurePolicy. Default is 'Fail'. Set it explicitly to 'Fail' or 'Ignore' to be intentional about webhook failure handling.", [input.metadata.name])
}

# RULE: failurePolicy must be a valid value
deny contains msg if {
	is_policy
	fp := spec.failurePolicy
	valid := {"Fail", "Ignore"}
	not fp in valid
	msg := sprintf("SPEC-004: Policy '%s' has invalid spec.failurePolicy '%s'. Must be 'Fail' or 'Ignore'.", [input.metadata.name, fp])
}

# RULE: webhookTimeoutSeconds should be set for complex policies
warn contains msg if {
	is_policy
	not has_field(spec, "webhookTimeoutSeconds")
	rules := object.get(spec, "rules", [])
	count(rules) > 3
	msg := sprintf("SPEC-005: Policy '%s' has %d rules but no spec.webhookTimeoutSeconds set. Consider setting a timeout for complex policies to avoid admission delays.", [input.metadata.name, count(rules)])
}

# RULE: webhookTimeoutSeconds should be between 1 and 30
deny contains msg if {
	is_policy
	timeout := spec.webhookTimeoutSeconds
	timeout < 1
	msg := sprintf("SPEC-006: Policy '%s' has spec.webhookTimeoutSeconds=%d. Must be between 1 and 30.", [input.metadata.name, timeout])
}

deny contains msg if {
	is_policy
	timeout := spec.webhookTimeoutSeconds
	timeout > 30
	msg := sprintf("SPEC-006: Policy '%s' has spec.webhookTimeoutSeconds=%d. Must be between 1 and 30.", [input.metadata.name, timeout])
}

# RULE: Warn if webhookTimeoutSeconds is very low
warn contains msg if {
	is_policy
	timeout := spec.webhookTimeoutSeconds
	timeout < 3
	timeout >= 1
	msg := sprintf("SPEC-007: Policy '%s' has a very low spec.webhookTimeoutSeconds=%d. This may cause premature timeouts under load.", [input.metadata.name, timeout])
}

# RULE: Warn if spec.validationFailureAction is used (deprecated)
warn contains msg if {
	is_policy
	has_field(spec, "validationFailureAction")
	msg := sprintf("SPEC-008: Policy '%s' uses spec.validationFailureAction which is deprecated. Migrate to per-rule validate.failureAction instead.", [input.metadata.name])
}

# RULE: Warn if spec.validationFailureActionOverrides is used (deprecated)
warn contains msg if {
	is_policy
	has_field(spec, "validationFailureActionOverrides")
	msg := sprintf("SPEC-009: Policy '%s' uses spec.validationFailureActionOverrides which is deprecated. Migrate to per-rule validate.failureActionOverrides instead.", [input.metadata.name])
}

# RULE: If validationFailureAction is used, it must be valid
deny contains msg if {
	is_policy
	vfa := spec.validationFailureAction
	valid := {"Audit", "Enforce", "audit", "enforce"}
	not vfa in valid
	msg := sprintf("SPEC-010: Policy '%s' has invalid spec.validationFailureAction '%s'. Must be 'Audit' or 'Enforce'.", [input.metadata.name, vfa])
}

# RULE: Warn if validationFailureAction is set to Audit in what looks like a security policy
warn contains msg if {
	is_policy
	vfa := spec.validationFailureAction
	lower(vfa) == "audit"
	category := annotations["policies.kyverno.io/category"]
	contains(lower(category), "security")
	msg := sprintf("SPEC-011: Policy '%s' is categorized as security but validationFailureAction is 'Audit'. Consider 'Enforce' for security policies in production.", [input.metadata.name])
}

# RULE: Warn if policy has too many rules (consider splitting)
warn contains msg if {
	is_policy
	rules := object.get(spec, "rules", [])
	count(rules) > 10
	msg := sprintf("SPEC-012: Policy '%s' has %d rules. Consider splitting into multiple smaller policies for maintainability and clarity.", [input.metadata.name, count(rules)])
}

# RULE: spec.applyRules should only be set to "One" or "All"
deny contains msg if {
	is_policy
	ar := spec.applyRules
	valid := {"One", "All"}
	not ar in valid
	msg := sprintf("SPEC-013: Policy '%s' has invalid spec.applyRules '%s'. Must be 'One' or 'All'.", [input.metadata.name, ar])
}

# RULE: Namespace-scoped Policy should not set namespace in metadata for ClusterPolicy
deny contains msg if {
	is_policy
	input.kind == "ClusterPolicy"
	input.metadata.namespace
	msg := sprintf("SPEC-014: ClusterPolicy '%s' should not have metadata.namespace set. ClusterPolicies are cluster-scoped resources.", [input.metadata.name])
}

# RULE: Policy (namespaced) should have a namespace
warn contains msg if {
	is_policy
	input.kind == "Policy"
	not input.metadata.namespace
	msg := sprintf("SPEC-015: Namespaced Policy '%s' does not specify metadata.namespace. It will default to 'default'. Set the namespace explicitly.", [input.metadata.name])
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

has_field(obj, key) if {
	_ := obj[key]
}
