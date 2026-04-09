---
title: Quickstart Guide
description: Quickstart Guide
---

### Example usage

```bash
argane eval file ./fixtures/baseline/invalid/host_process.yaml -p baseline

cat ./fixtures/restricted/invalid/capabilities.yaml | argane eval stdin

docker run -v ./fixtures:/fixtures kkrypt0nn/argane eval file /fixtures/baseline/valid/hostpath_volumes.yaml -p baseline
```
