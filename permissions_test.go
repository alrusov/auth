package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alrusov/config"
	"github.com/alrusov/misc"
)

//----------------------------------------------------------------------------------------------------------------------------//

func TestCheckPermissionsDenyWins(t *testing.T) {
	user := &Identity{User: "u1", Groups: []string{"g1", "g2"}}
	admin := &Identity{User: "adm", Groups: []string{"g1"}, IsAdmin: true}

	cases := []struct {
		name  string
		perms misc.BoolMap
		id    *Identity
		exp   bool
	}{
		{"empty", misc.BoolMap{}, user, false},
		{"nothing matches", misc.BoolMap{"u2": true, "@g3": true}, user, false},
		{"user allowed", misc.BoolMap{"u1": true}, user, true},
		{"group allowed", misc.BoolMap{"@g2": true}, user, true},
		{"all allowed", misc.BoolMap{"*": true}, user, true},
		{"user denied, all allowed", misc.BoolMap{"*": true, "u1": false}, user, false},
		{"group denied, all allowed", misc.BoolMap{"*": true, "@g1": false}, user, false},
		// раньше явное разрешение пользователя перекрывало запрет группы
		{"user allowed, group denied", misc.BoolMap{"u1": true, "@g2": false}, user, false},
		{"user allowed, all denied", misc.BoolMap{"u1": true, "*": false}, user, false},
		{"group allowed, other group denied", misc.BoolMap{"@g1": true, "@g2": false}, user, false},
		{"user denied, group allowed", misc.BoolMap{"u1": false, "@g1": true}, user, false},
		{"admin ignores deny", misc.BoolMap{"adm": false, "@g1": false, "*": false}, admin, true},
		{"admin with empty list", misc.BoolMap{}, admin, true},
	}

	for _, c := range cases {
		if got := c.id.checkPermissions(c.perms); got != c.exp {
			t.Errorf(`%s: expected %v, got %v`, c.name, c.exp, got)
		}
	}
}

//----------------------------------------------------------------------------------------------------------------------------//

func TestPasswordMatch(t *testing.T) {
	stored := string(Hash([]byte("secret"), []byte("u1")))

	cases := []struct {
		name   string
		stored string
		p      string
		hashed bool
		exp    bool
	}{
		{"plain ok", stored, "secret", false, true},
		{"plain wrong", stored, "secret2", false, false},
		{"plain empty", stored, "", false, false},
		{"hashed ok", stored, stored, true, true},
		{"hashed upper case", stored, strings.ToUpper(stored), true, true},
		{"hashed wrong", stored, stored[1:], true, false},
		// пользователь без пароля и пустой p в режиме хеша раньше пускались
		{"empty stored, empty hashed p", "", "", true, false},
		{"empty stored, plain p", "", "x", false, false},
	}

	for _, c := range cases {
		if got := PasswordMatch(c.stored, c.p, "u1", c.hashed); got != c.exp {
			t.Errorf(`%s: expected %v, got %v`, c.name, c.exp, got)
		}
	}
}

//----------------------------------------------------------------------------------------------------------------------------//

type errHandler struct{}

func (ah *errHandler) Init(cfg *config.Listener) error { return nil }
func (ah *errHandler) Enabled() bool                   { return true }
func (ah *errHandler) Score() int                      { return 1 }
func (ah *errHandler) WWWAuthHeader() (string, bool)   { return "test", false }
func (ah *errHandler) Check(id uint64, prefix string, path string, w http.ResponseWriter, r *http.Request) (*Identity, bool, error) {
	return nil, false, errors.New(`unknown user "u1"`)
}

func TestCheckHidesReason(t *testing.T) {
	hh := NewHandlers(&config.Listener{})
	if err := hh.Add(&errHandler{}); err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	_, code, msg := hh.Check(1, "", "/x", misc.BoolMap{"*": true}, httptest.NewRecorder(), r)

	if code != http.StatusUnauthorized {
		t.Errorf(`expected %d, got %d`, http.StatusUnauthorized, code)
	}
	if msg != "Unauthorised" {
		t.Errorf(`reason leaked to client: %q`, msg)
	}
}

//----------------------------------------------------------------------------------------------------------------------------//
