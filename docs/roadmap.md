# cryptodiff roadmap

This document captures forward-looking engineering direction for the scanner.

## Item R1: Multi-layer detection architecture (beyond regex-only)

### Goal

Evolve detection from a regex-only model to a layered model that supports language-aware and semantic detectors while preserving current artifact contracts and policy behavior.

### Why this matters

- Improve precision for high-impact rules (fewer false positives).
- Improve coverage for idiomatic code forms (fewer false negatives).
- Keep performance and portability expectations aligned with current scanner behavior.
- Enable incremental detector quality improvements without large rewrites.

### Incremental implementation plan

1. **Detector abstraction in scan pipeline**
   - Introduce detector interfaces and execution wiring so multiple detector types can run in a common pipeline.
   - Keep existing regex detectors as the baseline implementation under the new abstraction.

2. **Normalization and compatibility layer**
   - Normalize detector outputs (for example, min TLS versions) so policy matching and artifact schemas remain stable.
   - Preserve stable finding identity/fingerprint behavior where possible.

3. **First language-aware detector (Go TLS minimum version)**
   - Add a Go-aware detector for idiomatic `tls.Config` minimum-version usage.
   - Keep regex detection as fallback coverage for non-Go and config-file patterns.

4. **Confidence and explainability improvements**
   - Standardize confidence assignment by detector class (lexical vs language-aware).
   - Improve explainability of what was matched and why, without changing public artifact schema contracts.

5. **Progressive migration of high-value rules**
   - Promote additional precision-critical rules from regex-only to layered detection.
   - Maintain regression suites with explicit positive/negative fixtures for each rule.

### Delivery guardrails

- Preserve CLI behavior and existing artifact schema compatibility.
- Keep detector rollout incremental, test-driven, and benchmark-aware.
- Favor narrowly scoped changes with explicit regression coverage per rule.

## Item R2: GitHub Action distribution and versioning model

### Goal

Publish and maintain `cryptodiff` as a reusable GitHub Action with clear release semantics, secure pinning guidance, and predictable upgrade paths.

### Why this matters

- Reduce adoption friction for CI users who want `uses:`-based integration.
- Establish stable and understandable version channels for teams.
- Improve supply-chain safety posture for production CI usage.

### Incremental implementation plan

1. **Action packaging model**
   - Define how users consume the action (for example composite action wrapper and/or reusable workflow).
   - Keep local repo actions as the implementation source of truth.

2. **Release/tag strategy**
   - Publish immutable release tags (for example `v1.2.3`).
   - Maintain major channel tags (for example `v1`) that move to latest compatible release.
   - Document release cadence and compatibility expectations.

3. **Version pinning guidance**
   - Recommend commit-SHA pinning for high-assurance environments.
   - Provide examples for both SHA-pinned and major-tag consumption patterns.

4. **Artifact and provenance hardening**
   - Add reproducible release build steps for published binaries/action assets.
   - Add release notes that map scanner changes to action versions.

5. **Operational guardrails**
   - Add smoke tests for published action references.
   - Define deprecation policy for old major tags and migration guidance.

### Delivery guardrails

- Preserve backward compatibility for existing CI consumers within a major version.
- Keep versioning semantics explicit (`vX.Y.Z` immutable, `vX` movable).
- Keep docs synchronized with release automation and examples.
