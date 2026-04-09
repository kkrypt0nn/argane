# Argane

[![CI Badge](https://github.com/kkrypt0nn/argane/actions/workflows/ci.yaml/badge.svg)](https://github.com/kkrypt0nn/argane/actions)
[![Targeted Kubernetes Version Badge](https://img.shields.io/badge/Kubernetes-v1.35-326CE5?logo=kubernetes&logoColor=white)](https://kubernetes.io/blog/2025/12/17/kubernetes-v1-35-release/)
[![Go Report Card Badge](https://goreportcard.com/badge/github.com/kkrypt0nn/argane)](https://goreportcard.com/report/github.com/kkrypt0nn/argane)
[![Last Commit Badge](https://img.shields.io/github/last-commit/kkrypt0nn/argane)](https://github.com/kkrypt0nn/argane/commits/main)
[![Conventional Commits Badge](https://img.shields.io/badge/Conventional%20Commits-1.0.0-%23FE5196?logo=conventionalcommits&logoColor=white)](https://conventionalcommits.org/en/v1.0.0/)
[![Discord Server Badge](https://img.shields.io/discord/1358456011316396295?logo=discord)](https://discord.gg/xj6y5ZaTMr)

> [!CAUTION]
> **This project is under active development and is not yet ready for production use.**
> I strongly advise **not** using it until a stable release is published.
> **Contributions and feedback are more than welcome and appreciated once the core is complete.**

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

## Getting Started

### Installation

#### macOS

On macOS you can install the tool via the [Homebrew](https://brew.sh) Tap:

```bash
brew install kkrypt0nn/tap/argane

argane version
```

#### Docker

Provided you have Docker installed, you can pull the prebuilt image from Docker Hub or GitHub Container Registry:

```bash
docker pull docker.io/kkrypt0nn/argane
docker run docker.io/kkrypt0nn/argane version

# or

docker pull ghcr.io/kkrypt0nn/argane
docker run ghcr.io/kkrypt0nn/argane version
```

#### Prebuilt Binaries

Prebuilt binaries are available via GitHub Releases. Download the proper archive for your platform, extract and place the binary in one of the paths in your `PATH` environment variable.

##### macOS / Linux

```bash
ARCH=$(uname -m)
[ "$ARCH" = "x86_64" ] && ARCH=amd64
[ "$ARCH" = "aarch64" ] && ARCH=arm64

OS=$(uname -s | tr '[:upper:]' '[:lower:]')

curl -LO "https://github.com/kkrypt0nn/argane/releases/latest/download/argane_${OS}_${ARCH}.tar.gz"
tar -xzf "argane_${OS}_${ARCH}.tar.gz"
mv argane /usr/local/bin/

argane version
```

##### Windows

Go to the [releases](https://github.com/kkrypt0nn/argane/releases), download the ZIP file and extract it.

#### Go

Provided you have Go installed, you can execute the following command:

```bash
go install github.com/kkrypt0nn/argane/cmd/argane@latest
```

#### By source

To install the tool by source, provided you have cloned the repository, you can execute the following command:

```bash
make build

./dist/argane version # The binary is available in the dist folder
```

### Example Usage

```bash
argane eval file ./fixtures/baseline/invalid/host_process.yaml -p baseline

cat ./fixtures/restricted/invalid/capabilities.yaml | argane eval stdin

docker run -v ./fixtures:/fixtures kkrypt0nn/argane eval file /fixtures/baseline/valid/hostpath_volumes.yaml -p baseline
```

## Documentation

Coming soon!

## Troubleshooting

Issues are currently **disabled** while Argane is in active development and not ready for actual use.

Once a usable version is released, the issue tracker will be opened for bug reports, feature requests, and support.

## Contributing

Contributions are more than welcome, but please wait until we release a working beta or alpha version, then the issues will also be opened.

When it's time, please follow:
- [Contributing Guidelines](./CONTRIBUTING.md)
- [Code of Conduct](./CODE_OF_CONDUCT.md)

## License

This tool was made with 💜 by Krypton and is under the [Apache 2.0 License](./LICENSE.md).
