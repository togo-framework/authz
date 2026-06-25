<div align="center">
  <img src=".github/assets/togo-mark.svg" alt="togo" height="64" />
  <h1>togo-framework/authz</h1>
  <p>
    <a href="https://to-go.dev/marketplace"><img src="https://img.shields.io/badge/marketplace-to--go.dev-1FC7DC" alt="marketplace" /></a>
    <a href="https://pkg.go.dev/github.com/togo-framework/authz"><img src="https://pkg.go.dev/badge/github.com/togo-framework/authz.svg" alt="pkg.go.dev" /></a>
    <img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT" />
  </p>
  <p><strong>Authorization for <a href="https://to-go.dev">togo</a> — policies, gates & abilities, the layer above RBAC.</strong></p>
</div>

## Install

```bash
togo install togo-framework/authz
```

`authz` is the togo answer to Laravel Policies / Pundit / django-guardian. RBAC tells you a user's *roles*; `authz` decides the *specific* question **"may this subject perform this action on this resource?"** — ownership, tenancy, state, and any custom rule.

- **Policies** — per-resource-type, per-action rules (`update` a `Post` only if you authored it).
- **Gates** — standalone abilities with no specific resource (`access-admin`).
- **Before hooks** — short-circuit every check (super-admin bypass, maintenance lock).
- **Default deny** — unknown action/resource is denied; nothing is allowed by omission.

## Usage

```go
// Policies — keyed by authz.TypeName(resource), e.g. "*models.Post".
authz.Policy("*models.Post", map[string]authz.PolicyFunc{
    "update": func(ctx context.Context, subject, resource any) (bool, error) {
        return resource.(*models.Post).AuthorID == subject.(*models.User).ID, nil
    },
    "delete": func(ctx context.Context, subject, resource any) (bool, error) {
        return subject.(*models.User).Admin, nil
    },
})

// Gates — standalone abilities.
authz.RegisterGate("access-admin", func(ctx context.Context, s any) (bool, error) {
    return s.(*models.User).Admin, nil
})

// Before — super-admin bypass.
authz.Before(func(ctx context.Context, s any, action string) (decided, allow bool) {
    if u, ok := s.(*models.User); ok && u.SuperAdmin {
        return true, true
    }
    return false, false
})
```

### Checking access

```go
ok, err := authz.Can(ctx, user, "update", post)       // policy (resource non-nil)
ok2     := authz.Allows(ctx, user, "access-admin", nil) // gate (resource nil); error → deny
if err := authz.Authorize(ctx, user, "update", post); err != nil {
    return err // authz.ErrForbidden when denied
}
```

### Guarding routes

```go
ctx := authz.WithSubject(r.Context(), currentUser) // usually set by your auth middleware
r.With(authz.Require("access-admin")).Get("/admin", adminHandler) // 403 if denied
```

### REST + kernel

| Endpoint | |
|---|---|
| `GET /api/authz/can?action=<gate>` | gate check for the context subject |
| `GET /api/authz/abilities` | registered gates + policy types/actions |

`s, _ := authz.FromKernel(k)` returns the service (`Can` / `Allows` / `Authorize`).

## Configuration

No env required. Composes with `togo install togo-framework/auth` (read roles off the subject in your policies) but works standalone with any subject type.

---

<div align="center">
  <h3>Premium sponsors</h3>
  <p>
    <a href="https://id8media.com"><strong>ID8 Media</strong></a> &nbsp;·&nbsp;
    <a href="https://one-studio.co"><strong>One Studio</strong></a>
  </p>
  <p><sub>Support togo — <a href="https://github.com/sponsors/fadymondy">become a sponsor</a>.</sub></p>
</div>
