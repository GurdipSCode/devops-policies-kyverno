# Kyverno Policies

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Kyverno](https://img.shields.io/badge/Kyverno-v1.10+-green.svg)](https://kyverno.io/)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-v1.24+-blue.svg)](https://kubernetes.io/)
[![GitOps](https://img.shields.io/badge/GitOps-Ready-brightgreen.svg)](https://opengitops.dev/)
[![ArgoCD](https://img.shields.io/badge/ArgoCD-Compatible-orange.svg)](https://argoproj.github.io/cd/)
[![Flux](https://img.shields.io/badge/Flux-Compatible-blue.svg)](https://fluxcd.io/)
[![CI](https://img.shields.io/github/actions/workflow/status/your-org/kyverno-policies/validate.yml?label=CI)](https://github.com/your-org/kyverno-policies/actions)
[![Last Commit](https://img.shields.io/github/last-commit/your-org/kyverno-policies)](https://github.com/your-org/kyverno-policies/commits)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Code Style](https://img.shields.io/badge/code%20style-yamllint-blue)](https://yamllint.readthedocs.io/)

> 🛡️ A collection of Kyverno policies for Kubernetes cluster governance, security, and compliance - deployed via GitOps

---

## ✨ Features

- 🔒 **Security First**: Enforce pod security standards, image signing, and zero-trust networking
- ⚙️ **Best Practices**: Automated enforcement of Kubernetes best practices
- 📋 **Compliance Ready**: Pre-built policies for PCI-DSS, HIPAA, and more
- 🚀 **GitOps Native**: Designed for ArgoCD and Flux deployment
- 🧪 **CI/CD Tested**: Automated validation in your pipeline
- 📊 **Observable**: Built-in monitoring and reporting
- 🌍 **Multi-Environment**: Dev, staging, and production configurations
- 📦 **Modular**: Pick and choose policies that fit your needs

## 🎯 Why Kyverno?

Kyverno (Greek for "govern") is a CNCF project that makes Kubernetes policy management simple and declarative:

| Feature | Kyverno | Traditional Tools |
|---------|---------|-------------------|
| **Language** | Native YAML/Kubernetes | Custom DSL (Rego, etc.) |
| **Learning Curve** | ✅ Low - Uses K8s syntax | ⚠️ High - New language |
| **Validation** | ✅ Validate resources | ✅ Validate resources |
| **Mutation** | ✅ Modify resources | ⚠️ Limited |
| **Generation** | ✅ Create resources | ❌ Not supported |
| **GitOps** | ✅ Native support | ✅ Supported |
| **Reporting** | ✅ Built-in reports | ⚠️ External tools |

## 📋 Table of Contents

- [Features](#-features)
- [Why Kyverno?](#-why-kyverno)
- [Overview](#overview)
- [Policy Statistics](#-policy-statistics)
- [Quick Start](#-quick-start)
- [Example Policies](#-example-policies)
- [Repository Structure](#-repository-structure)
- [Policy Categories](#-policy-categories)
- [Prerequisites](#-prerequisites)
- [GitOps Deployment](#-gitops-deployment)
  - [ArgoCD](#argocd)
  - [Flux](#flux)
- [Policy Enforcement Modes](#️-policy-enforcement-modes)
- [Environment-Specific Configuration](#-environment-specific-configuration)
- [Testing Policies](#-testing-policies)
- [Monitoring and Reporting](#-monitoring-and-reporting)
- [Policy Development Guidelines](#-policy-development-guidelines)
- [GitOps Workflow](#-gitops-workflow)
- [Best Practices for GitOps](#-best-practices-for-gitops)
- [Contributing](#-contributing)
- [Useful Commands](#-useful-commands)
- [Resources](#-resources)
- [Support](#-support)
- [Troubleshooting](#-troubleshooting)
- [License](#-license)

## Overview

This repository contains [Kyverno](https://kyverno.io/) policies designed to enforce best practices, security standards, and compliance requirements across Kubernetes clusters. Kyverno is a policy engine designed specifically for Kubernetes, enabling declarative validation, mutation, and generation of resources.

## 📈 Policy Statistics

| Category | Policies | Status |
|----------|----------|--------|
| 🔒 Security | 15+ | ✅ Active |
| ⚙️ Best Practices | 20+ | ✅ Active |
| 📋 Compliance | 10+ | ✅ Active |
| **Total** | **45+** | **✅ Active** |

## ⚡ Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/your-org/kyverno-policies.git
cd kyverno-policies

# 2. Install Kyverno (if not already installed)
kubectl create -f https://github.com/kyverno/kyverno/releases/download/v1.10.0/install.yaml

# 3. Test policies locally
kyverno apply policies/ --resource tests/

# 4. Deploy via GitOps (see GitOps Deployment section)
```

## 📖 Example Policies

<details>
<summary><b>🔒 Require Read-Only Root Filesystem</b></summary>

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-ro-rootfs
  annotations:
    policies.kyverno.io/title: Require Read-Only Root Filesystem
    policies.kyverno.io/category: Security
    policies.kyverno.io/severity: medium
spec:
  validationFailureAction: Enforce
  rules:
  - name: validate-readOnlyRootFilesystem
    match:
      any:
      - resources:
          kinds:
          - Pod
    validate:
      message: "Root filesystem must be read-only"
      pattern:
        spec:
          containers:
          - securityContext:
              readOnlyRootFilesystem: true
```
</details>

<details>
<summary><b>⚙️ Require Resource Limits</b></summary>

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-resource-limits
  annotations:
    policies.kyverno.io/title: Require Resource Limits
    policies.kyverno.io/category: Best Practices
spec:
  validationFailureAction: Audit
  rules:
  - name: validate-resources
    match:
      any:
      - resources:
          kinds:
          - Pod
    validate:
      message: "CPU and memory resource limits are required"
      pattern:
        spec:
          containers:
          - resources:
              limits:
                memory: "?*"
                cpu: "?*"
```
</details>

<details>
<summary><b>📋 Require Labels</b></summary>

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-labels
  annotations:
    policies.kyverno.io/title: Require Labels
    policies.kyverno.io/category: Best Practices
spec:
  validationFailureAction: Enforce
  rules:
  - name: check-for-labels
    match:
      any:
      - resources:
          kinds:
          - Deployment
          - Service
    validate:
      message: "Required labels are missing"
      pattern:
        metadata:
          labels:
            app: "?*"
            env: "?*"
            team: "?*"
```
</details>

## 📁 Repository Structure

```
.
├── base/
│   └── kyverno/          # Kyverno installation (optional)
├── policies/
│   ├── kustomization.yaml
│   ├── security/         # Security-focused policies
│   ├── best-practices/   # General best practices
│   ├── compliance/       # Compliance and regulatory policies
│   └── custom/          # Organization-specific policies
├── overlays/
│   ├── dev/             # Development environment overrides
│   ├── staging/         # Staging environment overrides
│   └── production/      # Production environment overrides
├── tests/               # Policy test cases
└── README.md
```

## 📚 Policy Categories

### 🔒 Security Policies
- Container image validation and signing
- Pod security standards enforcement
- Network policy requirements
- Secret and ConfigMap management
- Privilege escalation prevention

### ⚙️ Best Practices
- Resource limits and requests
- Label and annotation requirements
- Namespace governance
- Deployment strategies
- Health check requirements

### 📋 Compliance
- Industry-specific compliance (PCI-DSS, HIPAA, etc.)
- Audit logging requirements
- Data residency rules
- Retention policies

## ✅ Prerequisites

- Kubernetes cluster (v1.24+)
- Kyverno installed (v1.10+)
- GitOps tool (ArgoCD or Flux) configured
- Git repository access

## 🚀 GitOps Deployment

This repository is designed to be deployed via GitOps using ArgoCD or Flux.

### ArgoCD

Create an Application manifest:

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: kyverno-policies
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://github.com/your-org/kyverno-policies
    targetRevision: main
    path: policies
  destination:
    server: https://kubernetes.default.svc
    namespace: kyverno
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
    - CreateNamespace=true
```

### Flux

Create a Kustomization:

```yaml
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata:
  name: kyverno-policies
  namespace: flux-system
spec:
  interval: 10m
  sourceRef:
    kind: GitRepository
    name: kyverno-policies
  path: ./policies
  prune: true
  wait: true
```

### Directory Structure for GitOps

```
.
├── policies/
│   ├── kustomization.yaml
│   ├── security/
│   │   ├── kustomization.yaml
│   │   └── *.yaml
│   ├── best-practices/
│   │   ├── kustomization.yaml
│   │   └── *.yaml
│   └── compliance/
│       ├── kustomization.yaml
│       └── *.yaml
└── overlays/              # Environment-specific overrides
    ├── dev/
    ├── staging/
    └── production/
```

## ⚖️ Policy Enforcement Modes

Policies can run in different validation failure actions:

- **Enforce**: Blocks resources that violate the policy
- **Audit**: Allows resources but generates policy violations
- **Warn**: Allows resources and displays warnings

To change enforcement mode, modify the `validationFailureAction` field in each policy.

## 🌍 Environment-Specific Configuration

Use overlays to customize policies per environment:

**Development** - Audit mode for most policies:
```yaml
# overlays/dev/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - ../../policies
patches:
  - patch: |-
      - op: replace
        path: /spec/validationFailureAction
        value: Audit
    target:
      kind: ClusterPolicy
```

**Production** - Enforce mode:
```yaml
# overlays/production/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - ../../policies
patches:
  - patch: |-
      - op: replace
        path: /spec/validationFailureAction
        value: Enforce
    target:
      kind: ClusterPolicy
```

## 🧪 Testing Policies

### Local Testing

Test policies locally before committing:

```bash
# Use Kyverno CLI to test policies
kyverno apply policies/ --resource tests/

# Test specific policy
kyverno apply policies/security/require-ro-rootfs.yaml --resource tests/pod-examples/
```

### CI/CD Integration

Example GitHub Actions workflow:

```yaml
name: Validate Kyverno Policies
on: [pull_request]
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install Kyverno CLI
        run: |
          curl -LO https://github.com/kyverno/kyverno/releases/download/v1.10.0/kyverno-cli_v1.10.0_linux_x86_64.tar.gz
          tar -xzf kyverno-cli_v1.10.0_linux_x86_64.tar.gz
          sudo mv kyverno /usr/local/bin/
      - name: Test Policies
        run: kyverno apply policies/ --resource tests/
      - name: Validate Manifests
        run: kyverno validate policies/
```

### Pre-commit Hooks

```bash
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: kyverno-validate
        name: Validate Kyverno Policies
        entry: kyverno validate
        language: system
        files: \.yaml$
        pass_filenames: true
```

## 📊 Monitoring and Reporting

### Policy Reports

View policy reports:

```bash
# Cluster-wide policy reports
kubectl get clusterpolicyreport -A

# Namespaced policy reports
kubectl get policyreport -n <namespace>

# View detailed violations
kubectl get clusterpolicyreport -o yaml
```

### GitOps Sync Status

Monitor deployment status through your GitOps tool:

**ArgoCD Dashboard**: Access via `https://argocd.yourdomain.com`
- View sync status and health
- See policy drift detection
- Review sync history

**Flux**: 
```bash
# Check if policies are up to date
flux get kustomizations
flux logs

# View alerts
flux get alerts
```

### Metrics and Observability

Kyverno exposes Prometheus metrics:

```yaml
# ServiceMonitor for Prometheus Operator
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: kyverno-metrics
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: kyverno
  endpoints:
    - port: metrics
```

Key metrics to monitor:
- `kyverno_policy_rule_results_total` - Policy execution results
- `kyverno_admission_requests_total` - Admission request count
- `kyverno_policy_execution_duration_seconds` - Policy execution time

## 📝 Policy Development Guidelines

1. **Clear naming**: Use descriptive names that indicate the policy's purpose
2. **Documentation**: Include detailed descriptions and rationale
3. **Annotations**: Add relevant metadata (severity, category, references)
4. **Testing**: Provide test cases for both compliant and non-compliant resources
5. **Exclusions**: Use namespace selectors to exclude system namespaces when appropriate

## 🔄 GitOps Workflow

```mermaid
graph LR
    A[👨‍💻 Developer] -->|1. Create Policy| B[🌿 Feature Branch]
    B -->|2. Test Locally| C[🧪 Kyverno CLI]
    C -->|3. Push & PR| D[📝 Pull Request]
    D -->|4. CI Validation| E[✅ GitHub Actions]
    E -->|5. Review| F[👥 Team Review]
    F -->|6. Merge| G[🔀 Main Branch]
    G -->|7. Auto Sync| H[🚀 GitOps Tool]
    H -->|8. Deploy| I[☸️ Kubernetes]
    I -->|9. Monitor| J[📊 Policy Reports]
```

### Workflow Steps

1. **Development**: Create/modify policies in feature branch
2. **Testing**: Run local tests using Kyverno CLI
3. **Pull Request**: Submit PR, automated tests run via CI/CD
4. **Review**: Team reviews policy changes and test results
5. **Merge**: Merge to main branch
6. **Deployment**: GitOps tool automatically syncs to clusters
7. **Monitor**: Check policy reports and metrics

### Rollback Strategy

If a policy causes issues:

```bash
# Via ArgoCD
argocd app rollback kyverno-policies

# Via Flux
flux reconcile kustomization kyverno-policies --with-source
```

Or revert the Git commit and let GitOps sync automatically.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-policy`)
3. Add or modify policies
4. Include test cases in `tests/` directory
5. Test locally with Kyverno CLI
6. Update documentation
7. Commit changes (`git commit -m 'Add: policy description'`)
8. Push to branch (`git push origin feature/new-policy`)
9. Submit a pull request
10. Wait for CI checks and team review
11. Once approved, merge triggers automatic deployment via GitOps

## 🔧 Useful Commands

### Kyverno Commands

```bash
# List all installed policies
kubectl get clusterpolicy,policy -A

# Describe a specific policy
kubectl describe clusterpolicy <policy-name>

# View policy status
kubectl get clusterpolicy <policy-name> -o jsonpath='{.status}'

# Delete a policy
kubectl delete clusterpolicy <policy-name>
```

### GitOps Commands

**ArgoCD:**
```bash
# Check sync status
argocd app get kyverno-policies

# Sync manually
argocd app sync kyverno-policies

# View sync history
argocd app history kyverno-policies

# Rollback to previous version
argocd app rollback kyverno-policies
```

**Flux:**
```bash
# Check reconciliation status
flux get kustomizations

# Force reconciliation
flux reconcile kustomization kyverno-policies --with-source

# Suspend reconciliation
flux suspend kustomization kyverno-policies

# Resume reconciliation
flux resume kustomization kyverno-policies
```

## 💡 Best Practices for GitOps

1. **Start with Audit Mode**: Deploy new policies in audit mode first, monitor reports, then switch to enforce
2. **Use Overlays**: Maintain environment-specific configurations using Kustomize overlays
3. **Version Control**: Tag releases for easy rollback (`git tag v1.0.0`)
4. **Namespace Exclusions**: Exclude critical namespaces (kube-system, kyverno, argocd, flux-system)
5. **Gradual Rollout**: Deploy to dev → staging → production
6. **Monitor Policy Reports**: Set up alerts for policy violations
7. **Document Exceptions**: Clearly document any policy exclusions or exceptions
8. **Regular Reviews**: Schedule periodic reviews of policies and violations
9. **Immutable Infrastructure**: Never modify policies directly in clusters
10. **Backup Policies**: Keep policies in version control (already done with Git!)

## 📚 Resources

### Kyverno
- [Kyverno Documentation](https://kyverno.io/docs/)
- [Kyverno Policy Library](https://kyverno.io/policies/)
- [Kyverno GitHub](https://github.com/kyverno/kyverno)
- [Kyverno Slack Channel](https://slack.k8s.io/)

### GitOps
- [ArgoCD Documentation](https://argo-cd.readthedocs.io/)
- [Flux Documentation](https://fluxcd.io/docs/)
- [GitOps Working Group](https://github.com/gitops-working-group/gitops-working-group)

### Kubernetes Policy
- [Kubernetes Policy Working Group](https://github.com/kubernetes/community/tree/master/wg-policy)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [NSA Kubernetes Hardening Guide](https://www.nsa.gov/Press-Room/News-Highlights/Article/Article/2716980/nsa-cisa-release-kubernetes-hardening-guidance/)

## 📄 License

[Specify your license here]

## 💬 Support

For issues and questions:

**Kyverno:**
- Open an issue in this repository
- [Kyverno Slack channel](https://slack.k8s.io/) (#kyverno)
- [Kyverno documentation](https://kyverno.io/docs/)

**GitOps Tools:**
- [ArgoCD Slack](https://argoproj.github.io/community/join-slack) (#argo-cd)
- [Flux Slack](https://fluxcd.io/#support) (#flux)

## 🔍 Troubleshooting

### Policies Not Syncing
- Check GitOps application status: `argocd app get kyverno-policies` or `flux get kustomizations`
- Verify repository access and credentials
- Check for YAML syntax errors in policies

### Policy Not Taking Effect
- Verify Kyverno is running: `kubectl get pods -n kyverno`
- Check policy status: `kubectl get clusterpolicy <policy-name> -o yaml`
- Review webhook configuration: `kubectl get validatingwebhookconfigurations`

### High Policy Execution Time
- Review policy complexity and optimize rules
- Consider using background scanning for expensive checks
- Monitor Kyverno resource usage

---

<div align="center">

### ⭐ Star this repository if you find it helpful!

**Made with ❤️ for the Kubernetes community**

[![GitHub stars](https://img.shields.io/github/stars/your-org/kyverno-policies?style=social)](https://github.com/your-org/kyverno-policies/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/your-org/kyverno-policies?style=social)](https://github.com/your-org/kyverno-policies/network/members)
[![GitHub watchers](https://img.shields.io/github/watchers/your-org/kyverno-policies?style=social)](https://github.com/your-org/kyverno-policies/watchers)

</div>

---

<div align="center">

**[Documentation](https://github.com/your-org/kyverno-policies/wiki)** • 
**[Contributing](CONTRIBUTING.md)** • 
**[Code of Conduct](CODE_OF_CONDUCT.md)** • 
**[Security](SECURITY.md)**

</div>
