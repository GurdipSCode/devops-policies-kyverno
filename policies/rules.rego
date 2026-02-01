# METADATA
# title: Kyverno Rule-Level Best Practices
# description: Validates individual rules within Kyverno policies
# related_resources:
#   - https://kyverno.io/docs/policy-types/cluster-policy/validate/
# authors:
#   - conftest-kyverno-linter

package main

import rego.v1

rules := object.get(object.get(input, "spec", {}), "rules", [])

# ============================================================================
# RULE NAMING
# ============================================================================

# RULE: Every rule must have a name
deny contains msg if {
	is_policy
	some i, rule in rules
	not rule.name
	msg := sprintf("RULE-001: Policy '%s', rule at index %d has no name. Every rule must have a descriptive name.", [input.metadata.name, i])
}

# RULE: Rule names should be descriptive (at least 5 characters)
warn contains msg if {
	is_policy
	some rule in rules
	rule.name
	count(rule.name) < 5
	msg := sprintf("RULE-002: Policy '%s', rule '%s' has a very short name (%d chars). Use a descriptive name (>= 5 chars).", [input.metadata.name, rule.name, count(rule.name)])
}

# RULE: Rule names should follow kebab-case or descriptive naming
warn contains msg if {
	is_policy
	some rule in rules
	rule.name
	regex.match(`\s`, rule.name)
	msg := sprintf("RULE-003: Policy '%s', rule '%s' contains whitespace. Use kebab-case (hyphenated) naming.", [input.metadata.name, rule.name])
}

# RULE: Rule names must be unique within the policy
deny contains msg if {
	is_policy
	some i, rule_a in rules
	some j, rule_b in rules
	i < j
	rule_a.name == rule_b.name
	msg := sprintf("RULE-004: Policy '%s' has duplicate rule name '%s' at indices %d and %d. Rule names must be unique.", [input.metadata.name, rule_a.name, i, j])
}

# ============================================================================
# MATCH BLOCK
# ============================================================================

# RULE: Every rule must have a match block
deny contains msg if {
	is_policy
	some rule in rules
	not has_field_rule(rule, "match")
	msg := sprintf("RULE-MATCH-001: Policy '%s', rule '%s' has no match block. Every rule must specify what resources to match.", [input.metadata.name, rule.name])
}

# RULE: Match block should specify resource kinds
deny contains msg if {
	is_policy
	some rule in rules
	rule.match
	match := rule.match

	# Check match.any
	any_items := object.get(match, "any", [])
	all_items := object.get(match, "all", [])

	# Also check old-style match.resources directly
	direct_resources := object.get(match, "resources", {})
	direct_kinds := object.get(direct_resources, "kinds", [])

	count(any_items) == 0
	count(all_items) == 0
	count(direct_kinds) == 0

	msg := sprintf("RULE-MATCH-002: Policy '%s', rule '%s' match block has no 'any', 'all', or 'resources.kinds' defined. Specify resource kinds to match.", [input.metadata.name, rule.name])
}

# RULE: Match resources.kinds should not be empty within any/all items
deny contains msg if {
	is_policy
	some rule in rules
	rule.match
	some item in object.get(rule.match, "any", [])
	resources := object.get(item, "resources", {})
	kinds := object.get(resources, "kinds", [])
	count(kinds) == 0
	msg := sprintf("RULE-MATCH-003: Policy '%s', rule '%s' has a match.any entry with empty resources.kinds.", [input.metadata.name, rule.name])
}

deny contains msg if {
	is_policy
	some rule in rules
	rule.match
	some item in object.get(rule.match, "all", [])
	resources := object.get(item, "resources", {})
	kinds := object.get(resources, "kinds", [])
	count(kinds) == 0
	msg := sprintf("RULE-MATCH-003: Policy '%s', rule '%s' has a match.all entry with empty resources.kinds.", [input.metadata.name, rule.name])
}

# RULE: Warn when matching wildcard kinds "*"
warn contains msg if {
	is_policy
	some rule in rules
	rule.match
	some item in object.get(rule.match, "any", [])
	resources := object.get(item, "resources", {})
	kinds := object.get(resources, "kinds", [])
	some k in kinds
	k == "*"
	msg := sprintf("RULE-MATCH-004: Policy '%s', rule '%s' matches all resource kinds ('*'). This is very broad and may have performance implications.", [input.metadata.name, rule.name])
}

warn contains msg if {
	is_policy
	some rule in rules
	rule.match
	some item in object.get(rule.match, "all", [])
	resources := object.get(item, "resources", {})
	kinds := object.get(resources, "kinds", [])
	some k in kinds
	k == "*"
	msg := sprintf("RULE-MATCH-004: Policy '%s', rule '%s' matches all resource kinds ('*'). This is very broad and may have performance implications.", [input.metadata.name, rule.name])
}

# ============================================================================
# EXCLUDE BLOCK
# ============================================================================

# RULE: Warn if ClusterPolicy matches broad kinds without exclude for system namespaces
warn contains msg if {
	is_policy
	input.kind == "ClusterPolicy"
	some rule in rules
	rule.match
	not has_field_rule(rule, "exclude")
	some item in object.get(rule.match, "any", [])
	resources := object.get(item, "resources", {})
	kinds := object.get(resources, "kinds", [])
	some k in kinds
	k in {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}
	namespaces := object.get(resources, "namespaces", [])
	count(namespaces) == 0
	msg := sprintf("RULE-EXCLUDE-001: ClusterPolicy '%s', rule '%s' matches '%s' across all namespaces with no exclude block. Consider excluding system namespaces (kube-system, kube-public, kube-node-lease, kyverno).", [input.metadata.name, rule.name, k])
}

# RULE: If exclude block exists, it should have content
warn contains msg if {
	is_policy
	some rule in rules
	rule.exclude
	exclude := rule.exclude
	any_items := object.get(exclude, "any", [])
	all_items := object.get(exclude, "all", [])
	direct_resources := object.get(exclude, "resources", {})
	count(any_items) == 0
	count(all_items) == 0
	count(direct_resources) == 0
	msg := sprintf("RULE-EXCLUDE-002: Policy '%s', rule '%s' has an empty exclude block. Either add exclusion criteria or remove the block.", [input.metadata.name, rule.name])
}

# ============================================================================
# VALIDATE RULES
# ============================================================================

# RULE: Validate rules must have a message
deny contains msg if {
	is_policy
	some rule in rules
	rule.validate
	validate := rule.validate
	not validate.message
	msg := sprintf("RULE-VALIDATE-001: Policy '%s', rule '%s' has a validate block but no message. Always provide a descriptive failure message for users.", [input.metadata.name, rule.name])
}

# RULE: Validate message should not be empty
deny contains msg if {
	is_policy
	some rule in rules
	rule.validate
	validate := rule.validate
	validate.message
	trimmed := trim_space(validate.message)
	trimmed == ""
	msg := sprintf("RULE-VALIDATE-002: Policy '%s', rule '%s' has an empty validate.message.", [input.metadata.name, rule.name])
}

# RULE: Validate message should be descriptive (at least 15 chars)
warn contains msg if {
	is_policy
	some rule in rules
	rule.validate
	validate := rule.validate
	validate.message
	trimmed := trim_space(validate.message)
	trimmed != ""
	count(trimmed) < 15
	msg := sprintf("RULE-VALIDATE-003: Policy '%s', rule '%s' has a very short validate.message (%d chars). Messages should clearly explain what is wrong and how to fix it.", [input.metadata.name, rule.name, count(trimmed)])
}

# RULE: Validate rules should have either pattern, anyPattern, deny, foreach, or cel
deny contains msg if {
	is_policy
	some rule in rules
	rule.validate
	validate := rule.validate
	not has_field_rule(validate, "pattern")
	not has_field_rule(validate, "anyPattern")
	not has_field_rule(validate, "deny")
	not has_field_rule(validate, "foreach")
	not has_field_rule(validate, "cel")
	msg := sprintf("RULE-VALIDATE-004: Policy '%s', rule '%s' validate block has no pattern, anyPattern, deny, foreach, or cel. At least one validation method is required.", [input.metadata.name, rule.name])
}

# RULE: Per-rule failureAction should be set for validate rules
warn contains msg if {
	is_policy
	some rule in rules
	rule.validate
	validate := rule.validate
	not has_field_rule(validate, "failureAction")

	# Only warn if the deprecated spec-level field is also not set
	not has_field_rule(object.get(input, "spec", {}), "validationFailureAction")
	msg := sprintf("RULE-VALIDATE-005: Policy '%s', rule '%s' does not set validate.failureAction and no spec-level validationFailureAction is set. Explicitly set failureAction to 'Audit' or 'Enforce'.", [input.metadata.name, rule.name])
}

# RULE: Per-rule failureAction must be a valid value
deny contains msg if {
	is_policy
	some rule in rules
	rule.validate
	fa := rule.validate.failureAction
	valid := {"Audit", "Enforce"}
	not fa in valid
	msg := sprintf("RULE-VALIDATE-006: Policy '%s', rule '%s' has invalid validate.failureAction '%s'. Must be 'Audit' or 'Enforce'.", [input.metadata.name, rule.name, fa])
}

# ============================================================================
# MUTATE RULES
# ============================================================================

# RULE: Mutate rules should have either patchStrategicMerge, patchesJson6902, or foreach
deny contains msg if {
	is_policy
	some rule in rules
	has_field_rule(rule, "mutate")
	mutate := rule.mutate
	not has_field_rule(mutate, "patchStrategicMerge")
	not has_field_rule(mutate, "patchesJson6902")
	not has_field_rule(mutate, "foreach")
	not has_field_rule(mutate, "targets")
	msg := sprintf("RULE-MUTATE-001: Policy '%s', rule '%s' mutate block has no patchStrategicMerge, patchesJson6902, foreach, or targets. At least one mutation method is required.", [input.metadata.name, rule.name])
}

# RULE: Warn about combining mutate and validate in the same rule
warn contains msg if {
	is_policy
	some rule in rules
	has_field_rule(rule, "mutate")
	has_field_rule(rule, "validate")
	msg := sprintf("RULE-MUTATE-002: Policy '%s', rule '%s' has both mutate and validate blocks. Consider separating these into different rules for clarity.", [input.metadata.name, rule.name])
}

# ============================================================================
# GENERATE RULES
# ============================================================================

# RULE: Generate rules must have either data or clone
deny contains msg if {
	is_policy
	some rule in rules
	has_field_rule(rule, "generate")
	gen := rule.generate
	not has_field_rule(gen, "data")
	not has_field_rule(gen, "clone")
	not has_field_rule(gen, "cloneList")
	not has_field_rule(gen, "generateExisting")
	msg := sprintf("RULE-GENERATE-001: Policy '%s', rule '%s' generate block has no data, clone, or cloneList. At least one generation source is required.", [input.metadata.name, rule.name])
}

# RULE: Generate rules should specify apiVersion and kind for the generated resource
deny contains msg if {
	is_policy
	some rule in rules
	has_field_rule(rule, "generate")
	gen := rule.generate
	not gen.kind
	msg := sprintf("RULE-GENERATE-002: Policy '%s', rule '%s' generate block does not specify the 'kind' of the resource to generate.", [input.metadata.name, rule.name])
}

# RULE: Warn about synchronize=true implications
warn contains msg if {
	is_policy
	some rule in rules
	has_field_rule(rule, "generate")
	gen := rule.generate
	gen.synchronize == true
	msg := sprintf("RULE-GENERATE-003: Policy '%s', rule '%s' uses generate.synchronize=true. Be aware that Kyverno will overwrite manual changes to the generated resource on each sync cycle.", [input.metadata.name, rule.name])
}

# ============================================================================
# PRECONDITIONS
# ============================================================================

# RULE: Warn if complex rules lack preconditions
warn contains msg if {
	is_policy
	some rule in rules
	rule.validate
	validate := rule.validate
	has_field_rule(validate, "deny")
	not has_field_rule(rule, "preconditions")
	msg := sprintf("RULE-PRECONDITION-001: Policy '%s', rule '%s' uses validate.deny without preconditions. Consider adding preconditions to narrow evaluation scope and improve performance.", [input.metadata.name, rule.name])
}

# RULE: Preconditions should use 'any' or 'all' (not the legacy list format)
warn contains msg if {
	is_policy
	some rule in rules
	has_field_rule(rule, "preconditions")
	pc := rule.preconditions
	is_array(pc)
	msg := sprintf("RULE-PRECONDITION-002: Policy '%s', rule '%s' uses the legacy list format for preconditions. Use the structured 'any'/'all' format instead.", [input.metadata.name, rule.name])
}

# ============================================================================
# CONTEXT
# ============================================================================

# RULE: Context variable names should follow a consistent naming convention
warn contains msg if {
	is_policy
	some rule in rules
	has_field_rule(rule, "context")
	some ctx in rule.context
	ctx.name
	regex.match(`\s`, ctx.name)
	msg := sprintf("RULE-CONTEXT-001: Policy '%s', rule '%s' has a context variable '%s' with whitespace. Use camelCase or snake_case.", [input.metadata.name, rule.name, ctx.name])
}

# RULE: Context entries should have a name
deny contains msg if {
	is_policy
	some rule in rules
	has_field_rule(rule, "context")
	some i, ctx in rule.context
	not ctx.name
	msg := sprintf("RULE-CONTEXT-002: Policy '%s', rule '%s' has a context entry at index %d without a name.", [input.metadata.name, rule.name, i])
}

# RULE: Warn about configMap context with no namespace
warn contains msg if {
	is_policy
	some rule in rules
	has_field_rule(rule, "context")
	some ctx in rule.context
	ctx.configMap
	not ctx.configMap.namespace
	msg := sprintf("RULE-CONTEXT-003: Policy '%s', rule '%s' context variable '%s' references a ConfigMap without specifying a namespace. It will default to the resource's namespace.", [input.metadata.name, rule.name, ctx.name])
}

# ============================================================================
# FOREACH
# ============================================================================

# RULE: Foreach must have a list
deny contains msg if {
	is_policy
	some rule in rules
	rule.validate
	validate := rule.validate
	has_field_rule(validate, "foreach")
	some i, fe in validate.foreach
	not fe.list
	msg := sprintf("RULE-FOREACH-001: Policy '%s', rule '%s' has a validate.foreach entry at index %d without a 'list' field.", [input.metadata.name, rule.name, i])
}

# ============================================================================
# HELPER
# ============================================================================

has_field_rule(obj, key) if {
	_ := obj[key]
}
