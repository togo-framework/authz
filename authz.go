// Package authz adds policy- and gate-based authorization to togo — the layer
// above RBAC (Laravel Policies / Pundit / django-guardian for togo).
//
// A POLICY answers "may this subject perform ACTION on this RESOURCE?" and is
// registered per resource type. A GATE answers a standalone ability with no
// specific resource ("may this subject access-admin?"). BEFORE hooks run first
// and can short-circuit every check (e.g. a super-admin bypass).
//
//	authz.Policy("models.Post", map[string]authz.PolicyFunc{
//	    "update": func(ctx context.Context, subject, resource any) (bool, error) {
//	        return resource.(*Post).AuthorID == subject.(*User).ID, nil
//	    },
//	})
//	ok, _ := authz.Can(ctx, user, "update", post)
package authz

import (
	"context"
	"fmt"
	"sync"
)

// PolicyFunc decides whether subject may perform action on a specific resource.
type PolicyFunc func(ctx context.Context, subject, resource any) (bool, error)

// GateFunc decides a standalone ability (no specific resource).
type GateFunc func(ctx context.Context, subject any) (bool, error)

// BeforeFunc runs before any check. If it returns decided=true its allow value
// short-circuits the whole check (use it for super-admin bypass, global locks…).
type BeforeFunc func(ctx context.Context, subject any, action string) (decided, allow bool)

var (
	mu       sync.RWMutex
	policies = map[string]map[string]PolicyFunc{} // resourceType -> action -> fn
	gates    = map[string]GateFunc{}
	befores  []BeforeFunc
)

// TypeName is the policy key derived from a resource value (e.g. "*models.Post").
// Register policies under the same string TypeName(resource) produces.
func TypeName(resource any) string { return fmt.Sprintf("%T", resource) }

// Policy registers per-action policies for a resource type. The key should match
// TypeName(resource) for the resources you'll check (e.g. "*models.Post").
func Policy(resourceType string, actions map[string]PolicyFunc) {
	mu.Lock()
	defer mu.Unlock()
	m := policies[resourceType]
	if m == nil {
		m = map[string]PolicyFunc{}
		policies[resourceType] = m
	}
	for a, fn := range actions {
		m[a] = fn
	}
}

// RegisterGate registers a standalone ability handler.
func RegisterGate(name string, fn GateFunc) {
	mu.Lock()
	gates[name] = fn
	mu.Unlock()
}

// Before registers a pre-check hook (evaluated in registration order).
func Before(fn BeforeFunc) {
	mu.Lock()
	befores = append(befores, fn)
	mu.Unlock()
}

// Reset clears all registered policies, gates and hooks (test helper).
func Reset() {
	mu.Lock()
	policies = map[string]map[string]PolicyFunc{}
	gates = map[string]GateFunc{}
	befores = nil
	mu.Unlock()
}

// Can reports whether subject may perform action. When resource is non-nil the
// decision uses the per-resource Policy registered for TypeName(resource);
// otherwise it uses the Gate named action. Unknown action/resource → deny.
// Before hooks are consulted first and can short-circuit.
func Can(ctx context.Context, subject any, action string, resource any) (bool, error) {
	mu.RLock()
	bs := append([]BeforeFunc(nil), befores...)
	mu.RUnlock()
	for _, b := range bs {
		if decided, allow := b(ctx, subject, action); decided {
			return allow, nil
		}
	}

	if resource != nil {
		mu.RLock()
		fn := policies[TypeName(resource)][action]
		mu.RUnlock()
		if fn == nil {
			return false, nil // default deny
		}
		return fn(ctx, subject, resource)
	}

	mu.RLock()
	g := gates[action]
	mu.RUnlock()
	if g == nil {
		return false, nil
	}
	return g(ctx, subject)
}

// Allows is Can with errors treated as deny — convenient in conditionals.
func Allows(ctx context.Context, subject any, action string, resource any) bool {
	ok, err := Can(ctx, subject, action, resource)
	return err == nil && ok
}

// Denies is the negation of Allows.
func Denies(ctx context.Context, subject any, action string, resource any) bool {
	return !Allows(ctx, subject, action, resource)
}

// Authorize returns ErrForbidden when the subject may not perform the action.
func Authorize(ctx context.Context, subject any, action string, resource any) error {
	ok, err := Can(ctx, subject, action, resource)
	if err != nil {
		return err
	}
	if !ok {
		return ErrForbidden
	}
	return nil
}

// ErrForbidden is returned by Authorize when access is denied.
var ErrForbidden = fmt.Errorf("authz: forbidden")
