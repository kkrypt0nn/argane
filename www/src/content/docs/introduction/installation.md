---
title: Installation
description: Installation
---

## macOS

You can install the tool via the [Homebrew](https://brew.sh) Tap:

```bash
brew install kkrypt0nn/tap/argane

argane version
```

## Docker

Provided you have Docker installed, you can pull the prebuilt image from Docker Hub or GitHub Container Registry:

```bash
docker pull docker.io/kkrypt0nn/argane
docker run docker.io/kkrypt0nn/argane version

# or

docker pull ghcr.io/kkrypt0nn/argane
docker run ghcr.io/kkrypt0nn/argane version
```

## Go

Provided you have Go installed, you can execute the following command:

```bash
go install github.com/kkrypt0nn/argane/cmd/argane@latest
```

## Prebuilt binaries

Prebuilt binaries are available via GitHub Releases. Download the proper archive for your platform, extract and place the binary in one of the paths in your `PATH` environment variable.

### macOS / Linux

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

### Windows

Go to the [releases](https://github.com/kkrypt0nn/argane/releases), download the ZIP file and extract it.

## Go

Provided you have Go installed, you can execute the following command:

```bash
go install github.com/kkrypt0nn/argane/cmd/argane@latest
```

## By source

Provided you have cloned the repository, you can execute the following command:

```bash
make build

./dist/argane version # The binary is available in the dist folder
```
