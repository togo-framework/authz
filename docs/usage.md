# authz — usage

## Policies (per-resource)
```go
authz.Policy("*models.Post", map[string]authz.PolicyFunc{
    "update": func(ctx context.Context, subject, resource any) (bool, error) {
        return resource.(*models.Post).AuthorID == subject.(*models.User).ID, nil
    },
    "delete": func(ctx context.Context, subject, resource any) (bool, error) {
        return subject.(*models.User).Admin, nil
    },
})
```
Register the key as `authz.TypeName(resource)` produces for your resource (e.g. `"*models.Post"`).

## Gates (standalone abilities)
```go
authz.RegisterGate("access-admin", func(ctx context.Context, subject any) (bool, error) {
    return subject.(*models.User).Admin, nil
})
```

## Before hooks (short-circuit)
```go
authz.Before(func(ctx context.Context, subject any, action string) (decided, allow bool) {
    if u, ok := subject.(*models.User); ok && u.SuperAdmin { return true, true } // bypass
    return false, false
})
```

## Checking
```go
ok, err := authz.Can(ctx, user, "update", post) // policy (resource non-nil)
ok2     := authz.Allows(ctx, user, "access-admin", nil) // gate (resource nil); error→deny
err     := authz.Authorize(ctx, user, "update", post)   // returns authz.ErrForbidden on deny
```

## HTTP middleware
```go
r.With(authz.Require("access-admin")).Get("/admin", handler) // 403 if denied
```
The subject is read from the request context — set it from your auth middleware:
```go
ctx := authz.WithSubject(r.Context(), currentUser)
```

## REST + kernel
- `GET /api/authz/can?action=<gate>` — gate check for the context subject
- `GET /api/authz/abilities` — registered gates + policy types/actions
- `s, _ := authz.FromKernel(k)` — the service (`Can`/`Allows`/`Authorize`)
