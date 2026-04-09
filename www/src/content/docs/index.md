---
title: Overview
description: Argane is a Kubernetes security validator for YAML manifests, Helm charts, and running pods.
---

<p style="display: flex; gap: 5px; flex-wrap: wrap;">
  <a href="https://github.com/kkrypt0nn/argane/actions">
    <img alt="CI Badge" src="https://github.com/kkrypt0nn/argane/actions/workflows/ci.yaml/badge.svg" />
  </a>
  <a href="https://kubernetes.io/blog/2025/12/17/kubernetes-v1-35-release/">
    <img alt="Targeted Kubernetes Version Badge" src="https://img.shields.io/badge/Kubernetes-v1.35-326CE5?logo=kubernetes&logoColor=white" />
  </a>
  <a href="https://goreportcard.com/report/github.com/kkrypt0nn/argane">
    <img alt="Go Report Card Badge" src="https://goreportcard.com/badge/github.com/kkrypt0nn/argane" />
  </a>
  <a href="https://github.com/kkrypt0nn/argane/commits/main">
    <img alt="Last Commit Badge" src="https://img.shields.io/github/last-commit/kkrypt0nn/argane" />
  </a>
  <a href="https://conventionalcommits.org/en/v1.0.0/">
    <img alt="Conventional Commits Badge" src="https://img.shields.io/badge/Conventional%20Commits-1.0.0-%23FE5196?logo=conventionalcommits&logoColor=white" />
  </a>
  <a href="https://discord.gg/xj6y5ZaTMr">
    <img alt="Discord Server Badge" src="https://img.shields.io/discord/1358456011316396295?logo=discord" />
  </a>
</p>

### 🕵️ Your Kubernetes pod security detective

**Argane** is a Kubernetes security validator for YAML manifests, Helm charts, and running pods. It checks your workloads against the [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/) and reports any violations, helping you identify security issues such as host namespaces, privileged containers, capabilities and other security settings.

Argane is designed to be a lightweight, developer-friendly tool that helps you catch pod security misconfigurations **early**, before they even reach your cluster.

## Features

- Validate workloads against Kubernetes Pod Security Standards (`privileged` or `baseline`)
- Multiple input sources are supported
  - YAML manifests
  - Rendered Helm charts
  - stdin
  - Running pods on a cluster
- Clear violation reporting with multiple output formatting including JSON
- Fast and CLI-friendly, built for CI pipelines
- Custom policies to give the possibility to extend the Kubernetes Pod Security Standards

## Goals

- Help developers and operators identify insecure pod configurations **before** deployment
- Enable security validation during code review and CI rather than only at runtime
- Stay as close as possible to the Kubernetes Pod Security Standards for more predictable and consistent results

## Non-goals

- Argane **does not** block workloads or enforce policies in-cluster, there are already amazing tools for that, including the built-in [admission enforcement](https://kubernetes.io/docs/concepts/security/pod-security-admission/) of Kubernetes
- Argane **is not** a vulnerability scanner and does not scan images for any kind of CVEs
