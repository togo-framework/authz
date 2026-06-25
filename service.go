package authz

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/togo-framework/togo"
)

// Service is the authz runtime stored on the kernel (k.Get("authz")). The
// policy/gate registries are package-global; the service exposes them over the
// kernel + REST and carries the kernel for integrations.
type Service struct {
	k *togo.Kernel
}

func init() {
	togo.RegisterProviderFunc("authz", togo.PriorityService, func(k *togo.Kernel) error {
		s := &Service{k: k}
		k.Set("authz", s)
		if k.Router != nil {
			s.mountRoutes(k.Router)
		}
		return nil
	})
}

// FromKernel returns the authz Service registered on the kernel.
func FromKernel(k *togo.Kernel) (*Service, bool) {
	v, ok := k.Get("authz")
	if !ok {
		return nil, false
	}
	s, ok := v.(*Service)
	return s, ok
}

// Can / Allows / Authorize on the service delegate to the package functions.
func (s *Service) Can(ctx context.Context, subject any, action string, resource any) (bool, error) {
	return Can(ctx, subject, action, resource)
}
func (s *Service) Allows(ctx context.Context, subject any, action string, resource any) bool {
	return Allows(ctx, subject, action, resource)
}
func (s *Service) Authorize(ctx context.Context, subject any, action string, resource any) error {
	return Authorize(ctx, subject, action, resource)
}

// ── Subject in request context ──

type ctxKey struct{}

// WithSubject stores the current subject (user) in the context. An auth
// middleware typically sets this; authz middleware reads it.
func WithSubject(ctx context.Context, subject any) context.Context {
	return context.WithValue(ctx, ctxKey{}, subject)
}

// SubjectFrom returns the subject stored by WithSubject (nil if none).
func SubjectFrom(ctx context.Context) any { return ctx.Value(ctxKey{}) }

// Require is HTTP middleware that allows the request only if the context subject
// passes the gate ability; otherwise it responds 403.
func Require(action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if Allows(r.Context(), SubjectFrom(r.Context()), action, nil) {
				next.ServeHTTP(w, r)
				return
			}
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
		})
	}
}

func (s *Service) mountRoutes(r chi.Router) {
	r.Route("/api/authz", func(r chi.Router) {
		// GET /api/authz/can?action=...  → gate check for the context subject.
		r.Get("/can", func(w http.ResponseWriter, req *http.Request) {
			action := req.URL.Query().Get("action")
			allowed := Allows(req.Context(), SubjectFrom(req.Context()), action, nil)
			writeJSON(w, http.StatusOK, map[string]any{"action": action, "allowed": allowed})
		})
		// GET /api/authz/abilities → list registered gate names + policy types.
		r.Get("/abilities", func(w http.ResponseWriter, req *http.Request) {
			writeJSON(w, http.StatusOK, Registry())
		})
	})
}

// Registry returns a snapshot of registered gates and policy types/actions.
func Registry() map[string]any {
	mu.RLock()
	defer mu.RUnlock()
	gateNames := make([]string, 0, len(gates))
	for n := range gates {
		gateNames = append(gateNames, n)
	}
	pol := map[string][]string{}
	for typ, actions := range policies {
		for a := range actions {
			pol[typ] = append(pol[typ], a)
		}
	}
	return map[string]any{"gates": gateNames, "policies": pol}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
