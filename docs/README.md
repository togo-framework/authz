# authz — docs

`togo-framework/authz` adds policy- and gate-based authorization on top of RBAC.

- **Install:** `togo install togo-framework/authz`
- **Marketplace:** https://to-go.dev/plugins/authz
- **Source:** https://github.com/togo-framework/authz

## Contents
- [Usage](usage.md) — policies, gates, before-hooks, Can/Authorize, middleware

A **policy** answers "may SUBJECT do ACTION on RESOURCE?" (per resource type); a
**gate** is a standalone ability. **Before** hooks short-circuit (super-admin
bypass). See [usage.md](usage.md).
