# METADATA
# title: Kyverno Policy Metadata Best Practices
# description: Validates metadata, labels, and annotations on Kyverno policies
# related_resources:
#   - https://kyverno.io/docs/policy-types/cluster-policy/
# authors:
#   - conftest-kyverno-linter

package main

import rego.v1

# ============================================================================
# HELPERS
# ============================================================================

is_kyverno_policy if {
	input.apiVersion == "kyverno.io/v1"
	input.kind in {"ClusterPolicy", "Policy"}
}

is_kyverno_v2_policy if {
	input.apiVersion == "kyverno.io/v2"
	input.kind in {"ClusterPolicy", "Policy"}
}

is_kyverno_v2beta1_policy if {
	input.apiVersion == "kyverno.io/v2beta1"
	input.kind in {"ClusterPolicy", "Policy"}
}

is_policy if {
	is_kyverno_policy
}

is_policy if {
	is_kyverno_v2_policy
}

is_policy if {
	is_kyverno_v2beta1_policy
}

annotations := object.get(input, ["metadata", "annotations"], {})

labels := object.get(input, ["metadata", "labels"], {})

# ============================================================================
# METADATA NAME
# ============================================================================

# RULE: Policy must have a metadata name
deny contains msg if {
	is_policy
	not input.metadata.name
	msg := "METADATA-001: Policy must have a metadata.name defined."
}

# RULE: Policy name should follow DNS naming convention (lowercase, hyphens)
deny contains msg if {
	is_policy
	name := input.metadata.name
	not regex.match(`^[a-z0-9]([a-z0-9\-]*[a-z0-9])?$`, name)
	msg := sprintf("METADATA-002: Policy name '%s' must be lowercase alphanumeric with hyphens only (DNS-compatible).", [name])
}

# RULE: Policy name should not exceed 63 characters (K8s limit)
deny contains msg if {
	is_policy
	name := input.metadata.name
	count(name) > 63
	msg := sprintf("METADATA-003: Policy name '%s' exceeds 63 characters. Kubernetes names must be <= 63 chars.", [name])
}

# ============================================================================
# REQUIRED ANNOTATIONS
# ============================================================================

# RULE: Policy must have a title annotation
deny contains msg if {
	is_policy
	not annotations["policies.kyverno.io/title"]
	msg := sprintf("ANNOTATION-001: Policy '%s' is missing annotation 'policies.kyverno.io/title'. Every policy should have a descriptive title.", [input.metadata.name])
}

# RULE: Policy must have a category annotation
deny contains msg if {
	is_policy
	not annotations["policies.kyverno.io/category"]
	msg := sprintf("ANNOTATION-002: Policy '%s' is missing annotation 'policies.kyverno.io/category'. Categorize your policy (e.g., 'Pod Security Standards', 'Best Practices', 'Multi-Tenancy').", [input.metadata.name])
}

# RULE: Policy must have a severity annotation
deny contains msg if {
	is_policy
	not annotations["policies.kyverno.io/severity"]
	msg := sprintf("ANNOTATION-003: Policy '%s' is missing annotation 'policies.kyverno.io/severity'. Severity should be 'low', 'medium', 'high', or 'critical'.", [input.metadata.name])
}

# RULE: Severity annotation must be a valid value
deny contains msg if {
	is_policy
	sev := annotations["policies.kyverno.io/severity"]
	valid_severities := {"low", "medium", "high", "critical"}
	not sev in valid_severities
	msg := sprintf("ANNOTATION-004: Policy '%s' has invalid severity '%s'. Must be one of: low, medium, high, critical.", [input.metadata.name, sev])
}

# RULE: Policy must have a subject annotation
deny contains msg if {
	is_policy
	not annotations["policies.kyverno.io/subject"]
	msg := sprintf("ANNOTATION-005: Policy '%s' is missing annotation 'policies.kyverno.io/subject'. Specify the resource subject (e.g., 'Pod', 'Deployment', 'Namespace').", [input.metadata.name])
}

# RULE: Policy must have a description annotation
deny contains msg if {
	is_policy
	not annotations["policies.kyverno.io/description"]
	msg := sprintf("ANNOTATION-006: Policy '%s' is missing annotation 'policies.kyverno.io/description'. Every policy should have a meaningful description.", [input.metadata.name])
}

# RULE: Description should not be empty
deny contains msg if {
	is_policy
	desc := annotations["policies.kyverno.io/description"]
	trimmed := trim_space(desc)
	trimmed == ""
	msg := sprintf("ANNOTATION-007: Policy '%s' has an empty 'policies.kyverno.io/description' annotation.", [input.metadata.name])
}

# RULE: Description should be at least 20 characters long
warn contains msg if {
	is_policy
	desc := annotations["policies.kyverno.io/description"]
	trimmed := trim_space(desc)
	trimmed != ""
	count(trimmed) < 20
	msg := sprintf("ANNOTATION-008: Policy '%s' has a very short description (%d chars). Consider making it more descriptive (>= 20 chars).", [input.metadata.name, count(trimmed)])
}

# RULE: Policy should have a kyverno version annotation
warn contains msg if {
	is_policy
	not annotations["kyverno.io/kyverno-version"]
	msg := sprintf("ANNOTATION-009: Policy '%s' is missing annotation 'kyverno.io/kyverno-version'. Specify the minimum Kyverno version tested.", [input.metadata.name])
}

# RULE: Policy should have a Kubernetes version annotation
warn contains msg if {
	is_policy
	not annotations["kyverno.io/kubernetes-version"]
	msg := sprintf("ANNOTATION-010: Policy '%s' is missing annotation 'kyverno.io/kubernetes-version'. Specify the target Kubernetes version.", [input.metadata.name])
}

# RULE: Policy should have a minversion annotation
warn contains msg if {
	is_policy
	not annotations["policies.kyverno.io/minversion"]
	msg := sprintf("ANNOTATION-011: Policy '%s' is missing annotation 'policies.kyverno.io/minversion'. Specify the minimum Kyverno version required.", [input.metadata.name])
}

# RULE: Title annotation should not be empty
deny contains msg if {
	is_policy
	title := annotations["policies.kyverno.io/title"]
	trimmed := trim_space(title)
	trimmed == ""
	msg := sprintf("ANNOTATION-012: Policy '%s' has an empty 'policies.kyverno.io/title' annotation.", [input.metadata.name])
}

# ============================================================================
# LABELS
# ============================================================================

# RULE: Policy should have labels for organizational management
warn contains msg if {
	is_policy
	count(labels) == 0
	msg := sprintf("LABEL-001: Policy '%s' has no labels. Consider adding labels for organizational management (e.g., 'app.kubernetes.io/managed-by', team ownership).", [input.metadata.name])
}
