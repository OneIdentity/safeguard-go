---
name: a2a-workflow
description: Stub reference for Safeguard A2A certificate-based workflows and related authentication boundaries.
---

# A2A Workflow

This is a Phase 0 stub to be expanded when A2A implementation begins. It covers credential retrieval and mutation, access-request brokering, and certificate-based dual authentication from `plan.md`.

- Retrieval workflows: passwords, private keys with `SshKeyFormat`, and API-key secrets.
- Set workflows: password and private-key updates through A2A.
- Brokered access requests must preserve client-certificate transport plus the appropriate authorization mode.
- `GetRetrievableAccounts` uses certificate user login, not A2A API-key authorization.
