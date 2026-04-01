# Changelog

All notable changes to the F1r3fly rust-client will be documented in this file.
This changelog is automatically generated from conventional commits.


## [0.2.0] - 2026-04-01

### Bug Fixes

- observer fallback uses --host/--port instead of hardcoded defaults, handle auto-propose nodes
- include language field in deploy signature projection
- update epoch-rewards smoke test to verify parsed output
- use HTTP API for epoch-rewards to parse full response data
- use correct URI rho:vault:system in test_systemvault.rho

### CI

- install protobuf-compiler for models build.rs
- add arch-specific RUSTFLAGS for gxhash (aes+neon on arm64)
- add build, test, and release workflows

### Documentation

- add API changelog for Jan-Mar 2026
- omit branch in library dependency example
- add library usage documentation to README

### Features

- align with f1r3node PR #398 - RevAddress → VaultAddress rename

### Refactoring

- address PR #10 review feedback

### Smoke_test

- build release first, portable timeout for macOS


