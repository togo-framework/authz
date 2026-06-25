---
name: authz
description: Add policy/gate authorization to a togo app with the authz plugin — define per-resource policies, standalone gates, super-admin before-hooks, and guard routes/handlers with Can/Authorize/Require.
---

# togo authz

Use the `togo-framework/authz` plugin for authorization beyond RBAC.

## Per-resource policy
```go
authz.Policy("*models.Post", map[string]authz.PolicyFunc{
  "update": func(ctx context.Context, subject, resource any) (bool, error) {
    return resource.(*models.Post).AuthorID == subject.(*models.User).ID, nil
  },
})
```
Key = `authz.TypeName(resource)` (e.g. `"*models.Post"`).

## Gate (standalone ability)
```go
authz.RegisterGate("access-admin", func(ctx context.Context, s any) (bool, error) { return s.(*models.User).Admin, nil })
```

## Super-admin bypass
```go
authz.Before(func(ctx context.Context, s any, action string) (bool, bool) {
  if u, ok := s.(*models.User); ok && u.SuperAdmin { return true, true }
  return false, false
})
```

## Check & guard
- `authz.Can(ctx, user, "update", post)` / `Allows(...)` (error→deny) / `Authorize(...)` (→ `ErrForbidden`)
- Route middleware: `r.With(authz.Require("access-admin"))...` (403 on deny); set subject via `authz.WithSubject(ctx, user)`.

## Tips
- Resource checks pass the resource (non-nil); abilities pass nil.
- Keep policies pure and fast; default is deny on unknown action/resource.
