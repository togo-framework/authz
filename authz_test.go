package authz

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type user struct {
	ID    int
	Admin bool
}

type post struct {
	AuthorID int
}

func setup() {
	Reset()
	Policy("*authz.post", map[string]PolicyFunc{
		"update": func(ctx context.Context, subject, resource any) (bool, error) {
			return resource.(*post).AuthorID == subject.(*user).ID, nil
		},
		"explode": func(ctx context.Context, subject, resource any) (bool, error) {
			return false, errors.New("boom")
		},
	})
	RegisterGate("access-admin", func(ctx context.Context, subject any) (bool, error) {
		u, _ := subject.(*user)
		return u != nil && u.Admin, nil
	})
}

func TestPolicyAllowDeny(t *testing.T) {
	setup()
	ctx := context.Background()
	owner := &user{ID: 1}
	other := &user{ID: 2}
	p := &post{AuthorID: 1}

	if !Allows(ctx, owner, "update", p) {
		t.Error("owner should be allowed to update own post")
	}
	if Allows(ctx, other, "update", p) {
		t.Error("non-owner must be denied")
	}
	if !Denies(ctx, other, "update", p) {
		t.Error("Denies should mirror !Allows")
	}
}

func TestUnknownActionDenies(t *testing.T) {
	setup()
	if Allows(context.Background(), &user{ID: 1}, "no-such-action", &post{}) {
		t.Error("unknown action must default-deny")
	}
}

func TestPolicyErrorIsDeny(t *testing.T) {
	setup()
	ok, err := Can(context.Background(), &user{ID: 1}, "explode", &post{})
	if err == nil {
		t.Error("expected error surfaced by Can")
	}
	if ok {
		t.Error("errored policy must not allow")
	}
	if Allows(context.Background(), &user{ID: 1}, "explode", &post{}) {
		t.Error("Allows must treat error as deny")
	}
}

func TestGate(t *testing.T) {
	setup()
	if !Allows(context.Background(), &user{Admin: true}, "access-admin", nil) {
		t.Error("admin should pass the gate")
	}
	if Allows(context.Background(), &user{Admin: false}, "access-admin", nil) {
		t.Error("non-admin must fail the gate")
	}
}

func TestBeforeHookBypass(t *testing.T) {
	setup()
	// Super-admin bypass: decide everything as allowed.
	Before(func(ctx context.Context, subject any, action string) (bool, bool) {
		if u, ok := subject.(*user); ok && u.Admin {
			return true, true
		}
		return false, false
	})
	other := &user{ID: 2, Admin: true} // not the owner, but admin
	if !Allows(context.Background(), other, "update", &post{AuthorID: 1}) {
		t.Error("before-hook should bypass the ownership policy for admins")
	}
}

func TestAuthorize(t *testing.T) {
	setup()
	if err := Authorize(context.Background(), &user{ID: 1}, "update", &post{AuthorID: 1}); err != nil {
		t.Errorf("owner Authorize should pass: %v", err)
	}
	if err := Authorize(context.Background(), &user{ID: 2}, "update", &post{AuthorID: 1}); !errors.Is(err, ErrForbidden) {
		t.Errorf("non-owner Authorize should be ErrForbidden, got %v", err)
	}
}

func TestRequireMiddleware(t *testing.T) {
	setup()
	h := Require("access-admin")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Admin subject → 200
	req := httptest.NewRequest("GET", "/admin", nil)
	req = req.WithContext(WithSubject(req.Context(), &user{Admin: true}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("admin should pass middleware, got %d", rec.Code)
	}

	// Non-admin → 403
	req2 := httptest.NewRequest("GET", "/admin", nil)
	req2 = req2.WithContext(WithSubject(req2.Context(), &user{Admin: false}))
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusForbidden {
		t.Errorf("non-admin should get 403, got %d", rec2.Code)
	}
}

func TestRegistry(t *testing.T) {
	setup()
	reg := Registry()
	gates, _ := reg["gates"].([]string)
	if len(gates) != 1 || gates[0] != "access-admin" {
		t.Errorf("registry gates = %v", reg["gates"])
	}
}
