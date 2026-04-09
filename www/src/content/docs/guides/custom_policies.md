---
title: Custom Policies
description: Create your own Pod Security policies and extend existing standards.
---

:::note

_Currently_ custom policies can only be applied to a pod `spec`, so there is no way to check for example if a label is set. It is however planned to allow something like that in the future.

:::

Argane allows you to define your own policies using YAML. Custom policies let you:

- Extend existing Pod Security Standard policies (`baseline` or `restricted`)
- Add additional validation rules
- Customize allowed or denied values for specific fields

This makes it possible to enforce organization-specific security requirements while still benefiting from the built-in Pod Security Standards.

To use a custom policy file you can simply pass it in the `-p/--policy` command flag on the [`eval`](/commands/argane_eval/) commands.

## Extending existing standards/policies

A custom policy can extend an existing policy using the `extends` field. The supported base policies `baseline` and `restricted`. When a policy is extended, Argane loads all rules from the base policy and then applies your custom rules on top.

Example:

```yaml
extends: baseline

rules:
  - id: custom:no-host-network
    path: hostNetwork
    deniedValues:
      - "true"
```

In this example:

1. All **baseline** rules are applied
2. The custom `custom:no-host-network` rule is added

## Custom rules

Custom rules allow you to validate specific fields inside the Kubernetes pod `spec`.

Each rule contains:

| Field           | Description                             |
| --------------- | --------------------------------------- |
| `id`            | Unique identifier for the rule          |
| `path`          | Path to the field inside the pod `spec` |
| `allowedValues` | Optional list of allowed values         |
| `deniedValues`  | Optional list of denied values          |

:::note

`allowedValues` and `deniedValues` _currently_ only support exact value matching. Regular expressions or wildcard patterns are not yet supported.

:::

Example:

```yaml
rules:
  - id: custom:disallow-host-pid
    path: hostPID
    deniedValues:
      - "true"
```

If `hostPID` is set to `true`, Argane will report a violation.

## Targeting container fields

Rules can also target fields inside containers using array paths.

Example:

```yaml
rules:
  - id: custom:deny-privileged
    path: containers[*].securityContext.privileged
    deniedValues:
      - "true"
```

This checks every container in the pod.
