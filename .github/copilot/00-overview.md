# Overview

This repository contains a Juju Kubernetes charm responsible for managing the `opentelemetry-collector` workload.  
The charm follows a consistent architectural pattern based on a reconciler loop, strict idempotency, and clear separation between charm logic and workload logic.

## Purpose of These Instructions
These documents provide Copilot with the architectural rules, patterns, testing conventions, and domain knowledge required to generate correct, maintainable charm code and assist with debugging issues.  
Copilot should prioritize the patterns described here over generic Juju or Python examples.

## Key Concepts
- Reconciler-driven charm architecture  
- Observed vs. desired state  
- Idempotent workload operations  
- Structured ops.testing tests  
- Opinionated CI/CD expectations
