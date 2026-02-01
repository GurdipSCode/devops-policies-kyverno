# METADATA
# title: Kyverno Policy Operational & Performance Best Practices
# description: Checks for operational hygiene, performance, and maintainability
# related_resources:
#   - https://kyverno.io/docs/policy-types/cluster-policy/tips/
# authors:
#   - conftest-kyverno-linter

package main

import rego.v1

# ============================================================================
# PERFORMANCE
# ============================================================================

# RULE: Avoid matching too many resource kinds in a single rule
warn contains msg if {
	is_policy
	some rule in rules
	rule.match
	some item in object.get(rule.match, "any", [])
	resources := object.get(item, "resources", {})
	kinds := object.get(resources, "kinds", [])
	count(kinds) > 5
	msg := sprintf("PERF-001: Policy '%s', rule '%s' matches %d resource kinds in a single match entry. Consider splitting into multiple rules for clarity and webhook efficiency.", [input.metadata.name, rule.name, count(kinds)])
}

# RULE: Warn about API calls in context without caching awareness
warn contains msg if {
	is_policy
	some rule in rules
	has_field_ops(rule, "context")
	some ctx in rule.context
	has_field_ops(ctx, "apiCall")
	msg := sprintf("PERF-002: Policy '%s', rule '%s' uses apiCall context variable '%s'. API calls add latency to admission requests. Ensure the endpoint is responsive and consider caching strategies.", [input.metadata.name, rule.name, ctx.name])
}

# RULE: Warn about imageRegistry context lookups (can be slow)
warn contains msg if {
	is_policy
	some rule in rules
	has_field_ops(rule, "context")
	some ctx in rule.context
	has_field_ops(ctx, "imageRegistry")
	msg := sprintf("PERF-003: Policy '%s', rule '%s' uses imageRegistry context variable '%s'. Registry lookups add external latency to admissions. Ensure timeouts are appropriate.", [input.metadata.name, rule.name, ctx.name])
}

# RULE: Multiple API calls in same rule can compound latency
warn contains msg if {
	is_policy
	some rule in rules
	has_field_ops(rule, "context")
	api_calls := [ctx |
		some ctx in rule.context
		has_field_ops(ctx, "apiCall")
	]
	count(api_calls) > 2
	msg := sprintf("PERF-004: Policy '%s', rule '%s' has %d API call context variables. Multiple API calls can significantly increase admission latency.", [input.metadata.name, rule.name, count(api_calls)])
}

# RULE: Foreach with nested foreach can be expensive
warn contains msg if {
	is_policy
	some rule in rules
	rule.validate
	validate := rule.validate
	has_field_ops(validate, "foreach")
	some fe in validate.foreach
	has_field_ops(fe, "foreach")
	msg := sprintf("PERF-005: Policy '%s', rule '%s' has nested foreach in validation. Nested loops can be expensive for resources with many items.", [input.metadata.name, rule.name])
}

# ============================================================================
# OPERATIONAL HYGIENE
# ============================================================================

# RULE: Policy should use a consistent apiVersion
warn contains msg if {
	is_policy
	input.apiVersion == "kyverno.io/v2beta1"
	msg := sprintf("OPS-001: Policy '%s' uses apiVersion 'kyverno.io/v2beta1'. Consider migrating to the stable 'kyverno.io/v1' or 'kyverno.io/v2' API.", [input.metadata.name])
}

# RULE: Avoid using deprecated match.resources format directly
warn contains msg if {
	is_policy
	some rule in rules
	rule.match
	match := rule.match

	# Old format: match.resources.kinds directly (not inside any/all)
	has_field_ops(match, "resources")
	not has_field_ops(match, "any")
	not has_field_ops(match, "all")
	msg := sprintf("OPS-002: Policy '%s', rule '%s' uses the legacy match.resources format. Prefer the structured match.any/match.all format for clarity.", [input.metadata.name, rule.name])
}

# RULE: Warn about rules that don't specify operations (CREATE, UPDATE, DELETE, CONNECT)
warn contains msg if {
	is_policy
	some rule in rules
	rule.match
	some item in object.get(rule.match, "any", [])
	resources := object.get(item, "resources", {})
	not has_field_ops(resources, "operations")
	msg := sprintf("OPS-003: Policy '%s', rule '%s' does not specify match operations (CREATE, UPDATE, DELETE, CONNECT). Without this, the rule matches all operations, which may be broader than intended.", [input.metadata.name, rule.name])
}

# RULE: Warn about overly broad namespace selectors
warn contains msg if {
	is_policy
	some rule in rules
	rule.match
	some item in object.get(rule.match, "any", [])
	resources := object.get(item, "resources", {})
	has_field_ops(resources, "namespaceSelector")
	ns_selector := resources.namespaceSelector
	match_labels := object.get(ns_selector, "matchLabels", {})
	match_exprs := object.get(ns_selector, "matchExpressions", [])
	count(match_labels) == 0
	count(match_exprs) == 0
	msg := sprintf("OPS-004: Policy '%s', rule '%s' has an empty namespaceSelector, which matches all namespaces. Be explicit about which namespaces should be targeted.", [input.metadata.name, rule.name])
}

# RULE: Mutate + Generate in the same policy may have ordering issues
warn contains msg if {
	is_policy
	has_mutate := [r | some r in rules; has_field_ops(r, "mutate")]
	has_generate := [r | some r in rules; has_field_ops(r, "generate")]
	count(has_mutate) > 0
	count(has_generate) > 0
	msg := sprintf("OPS-005: Policy '%s' contains both mutate and generate rules. Consider separating them into different policies to avoid ordering confusion.", [input.metadata.name])
}

# RULE: Validate + Mutate in the same policy (different rules) is okay but worth noting
warn contains msg if {
	is_policy
	has_mutate := [r | some r in rules; has_field_ops(r, "mutate")]
	has_validate := [r | some r in rules; has_field_ops(r, "validate")]
	count(has_mutate) > 0
	count(has_validate) > 0
	msg := sprintf("OPS-006: Policy '%s' contains both mutate and validate rules. Note that Kyverno applies all mutation rules before validation rules across all policies.", [input.metadata.name])
}

# RULE: Warn about rules with no clear action (no validate, mutate, generate, or verifyImages)
deny contains msg if {
	is_policy
	some rule in rules
	not has_field_ops(rule, "validate")
	not has_field_ops(rule, "mutate")
	not has_field_ops(rule, "generate")
	not has_field_ops(rule, "verifyImages")
	msg := sprintf("OPS-007: Policy '%s', rule '%s' has no validate, mutate, generate, or verifyImages block. Every rule must perform at least one action.", [input.metadata.name, rule.name])
}

# ============================================================================
# IMAGE VERIFICATION
# ============================================================================

# RULE: verifyImages should specify attestors or authorities
warn contains msg if {
	is_policy
	some rule in rules
	has_field_ops(rule, "verifyImages")
	some i, vi in rule.verifyImages
	not has_field_ops(vi, "attestors")
	not has_field_ops(vi, "attestations")
	msg := sprintf("OPS-008: Policy '%s', rule '%s', verifyImages entry %d has no attestors or attestations defined. Image verification without attestors has limited security value.", [input.metadata.name, rule.name, i])
}

# RULE: verifyImages should specify imageReferences
deny contains msg if {
	is_policy
	some rule in rules
	has_field_ops(rule, "verifyImages")
	some i, vi in rule.verifyImages
	not has_field_ops(vi, "imageReferences")
	not has_field_ops(vi, "image")
	msg := sprintf("OPS-009: Policy '%s', rule '%s', verifyImages entry %d has no imageReferences or image specified. You must specify which images to verify.", [input.metadata.name, rule.name, i])
}

# ============================================================================
# AUTOGEN ANNOTATIONS
# ============================================================================

# RULE: Check for deprecated pod-policies.kyverno.io/autogen-controllers annotation
warn contains msg if {
	is_policy
	annotations["pod-policies.kyverno.io/autogen-controllers"]
	msg := sprintf("OPS-010: Policy '%s' uses the deprecated 'pod-policies.kyverno.io/autogen-controllers' annotation. Use spec.rules[].match with appropriate controller kinds, or use 'kyverno.io/autogen-controllers'.", [input.metadata.name])
}

# ============================================================================
# RESOURCE FILTERS
# ============================================================================

# RULE: Warn about matching Secrets without restricting operations
warn contains msg if {
	is_policy
	some rule in rules
	rule.match
	matches_kind_ops(rule, "Secret")
	some item in object.get(rule.match, "any", [])
	resources := object.get(item, "resources", {})
	not has_field_ops(resources, "operations")
	msg := sprintf("OPS-011: Policy '%s', rule '%s' matches Secrets without restricting operations. This will trigger on every Secret CREATE/UPDATE/DELETE/CONNECT. Be specific about which operations matter.", [input.metadata.name, rule.name])
}

# RULE: Warn about matching ConfigMaps without restricting operations
warn contains msg if {
	is_policy
	some rule in rules
	rule.match
	matches_kind_ops(rule, "ConfigMap")
	some item in object.get(rule.match, "any", [])
	resources := object.get(item, "resources", {})
	not has_field_ops(resources, "operations")
	msg := sprintf("OPS-012: Policy '%s', rule '%s' matches ConfigMaps without restricting operations. ConfigMaps are frequently updated; restrict operations to avoid unnecessary webhook calls.", [input.metadata.name, rule.name])
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

has_field_ops(obj, key) if {
	_ := obj[key]
}

matches_kind_ops(rule, kind) if {
	some item in object.get(rule.match, "any", [])
	resources := object.get(item, "resources", {})
	kinds := object.get(resources, "kinds", [])
	some k in kinds
	k == kind
}

matches_kind_ops(rule, kind) if {
	some item in object.get(rule.match, "all", [])
	resources := object.get(item, "resources", {})
	kinds := object.get(resources, "kinds", [])
	some k in kinds
	k == kind
}

matches_kind_ops(rule, kind) if {
	resources := object.get(rule.match, "resources", {})
	kinds := object.get(resources, "kinds", [])
	some k in kinds
	k == kind
}
