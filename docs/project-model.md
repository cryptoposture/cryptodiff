## Project model

`cryptodiff` is the open-code scanner component of the broader `cryptoposture` product strategy.

### What is in this repository

- CLI scanner and audit workflow (`scan`, `diff`, `audit`, `baseline`, `explain`)
- Artifact contracts (JSON/SARIF/CBOM) and embedded schema validation
- Default policy and exception primitives
- CI integration examples and local GitHub composite actions

### What is not in this repository

The `cryptoposture` control plane is intentionally out of scope and proprietary.
Examples of expected proprietary capabilities include:

- Hosted organization and tenant management
- Policy lifecycle orchestration across many repositories
- Centralized exception workflows and approvals
- Enterprise reporting, analytics, and integrations

### Licensing and usage posture

This repository is public for transparency, integration trust, and developer adoption.
It is not currently published under an OSI open-source license.
Use, redistribution, and modification rights are governed by `LICENSE`.

### Contribution expectations

Community feedback and issues are welcome.
Any future external contribution workflow (for example, contribution terms and review policy) will be documented before accepting third-party code contributions.
