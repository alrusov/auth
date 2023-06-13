package auth

import (
	"fmt"
	"net/http"
	"sync"

	"github.com/alrusov/config"
	"github.com/alrusov/log"
	"github.com/alrusov/misc"
)

//----------------------------------------------------------------------------------------------------------------------------//

type (
	// Handlers --
	Handlers struct {
		mutex *sync.RWMutex
		cfg   *config.Listener
		list  []Handler
	}

	// Handler --
	Handler interface {
		Init(lCfg *config.Listener) error
		Enabled() bool
		Score() int
		WWWAuthHeader() (name string, withRealm bool)
		Check(id uint64, prefix string, path string, w http.ResponseWriter, r *http.Request) (identity *Identity, tryNext bool, err error)
	}

	// Identity --
	Identity struct {
		Method  string
		User    string
		Groups  []string
		Extra   any
		Type    string
		IsAdmin bool
	}

	IdentityProvider interface {
		Init(aCfg *config.Auth) (err error)
		GetIdentity(u string) (identity *Identity, err error)
		Check(u string, p string, hashedPassword bool) (identity *Identity, exists bool, err error)
	}
)

const (
	// HTTP заголовок
	Header = "Authorization"
)

var (
	// Log --
	Log = log.NewFacility("stdhttp.auth")

	stdIdentityProviders []IdentityProvider
)

//----------------------------------------------------------------------------------------------------------------------------//

// NewHandlers --
func NewHandlers(cfg *config.Listener) *Handlers {
	if len(stdIdentityProviders) == 0 {
		provider := &LocalIdentityProvider{}
		_ = AddStdIdentityProvider(provider, &cfg.Auth)
	}

	return &Handlers{
		mutex: new(sync.RWMutex),
		cfg:   cfg,
	}
}

//----------------------------------------------------------------------------------------------------------------------------//

// Add --
func (hh *Handlers) Add(ah Handler) (err error) {
	hh.mutex.Lock()
	defer hh.mutex.Unlock()

	err = ah.Init(hh.cfg)
	if err != nil {
		return
	}

	if ah.Enabled() {
		hh.add(ah)
		return
	}

	return
}

func (hh *Handlers) add(ah Handler) {
	ln := len(hh.list)

	if ln == 0 {
		hh.list = []Handler{ah}
		return
	}

	score := ah.Score()

	i := 0
	for ; i < ln; i++ {
		if hh.list[i].Score() > score {
			break
		}
	}

	if i == 0 {
		hh.list = append([]Handler{ah}, hh.list...)
		return
	}

	if i == ln {
		hh.list = append(hh.list, ah)
		return
	}

	hh.list = append(hh.list, nil)
	copy(hh.list[i+1:], hh.list[i:])
	hh.list[i] = ah
}

//----------------------------------------------------------------------------------------------------------------------------//

// Enabled --
func (hh *Handlers) Enabled() bool {
	hh.mutex.RLock()
	defer hh.mutex.RUnlock()

	return len(hh.list) > 0
}

//----------------------------------------------------------------------------------------------------------------------------//

// WriteAuthRequestHeaders --
func (hh *Handlers) WriteAuthRequestHeaders(w http.ResponseWriter, prefix string, path string) {
	hh.mutex.RLock()
	defer hh.mutex.RUnlock()

	if len(hh.list) == 0 {
		return
	}

	for _, ah := range hh.list {
		name, withRealm := ah.WWWAuthHeader()
		if name == "" {
			continue
		}

		s := name
		if withRealm {
			s = fmt.Sprintf(`%s realm="%s%s"`, name, prefix, path)
		}

		w.Header().Add("WWW-Authenticate", s)
	}
}

//----------------------------------------------------------------------------------------------------------------------------//

// Check --
func (hh *Handlers) Check(id uint64, prefix string, path string, permissions misc.BoolMap, w http.ResponseWriter, r *http.Request) (identity *Identity, code int, msg string) {
	hh.mutex.RLock()
	defer hh.mutex.RUnlock()

	code = 0

	if len(hh.list) == 0 {
		return
	}

	tryNext := false
	var err error
	for _, ah := range hh.list {
		identity, tryNext, err = ah.Check(id, prefix, path, w, r)

		if identity != nil {
			if !identity.checkPermissions(permissions) {
				code = http.StatusForbidden
				msg = "Forbidden"
			}
			return
		}

		if !tryNext {
			break
		}
	}

	code = http.StatusUnauthorized
	if err != nil {
		msg = err.Error()
		return
	}
	msg = "Unauthorised"
	return
}

//----------------------------------------------------------------------------------------------------------------------------//

func (identity *Identity) checkPermissions(permissions misc.BoolMap) bool {
	if len(permissions) == 0 {
		return false
	}

	user := identity.User

	p, exists := permissions[user]
	if exists {
		return p
	}

	if len(identity.Groups) > 0 {
		enabled := false

		for _, g := range identity.Groups {
			p, exists := permissions["@"+g]
			if exists {
				if !p {
					return false
				}
				enabled = true
			}
		}

		if enabled {
			return true
		}
	}

	p, exists = permissions["*"]
	if exists {
		return p
	}

	return false
}

//----------------------------------------------------------------------------------------------------------------------------//

// Hash --
func Hash(p []byte, salt []byte) []byte {
	return misc.Sha512Hash(append(p, salt...))
}

//----------------------------------------------------------------------------------------------------------------------------//

func AddStdIdentityProvider(provider IdentityProvider, aCfg *config.Auth) (err error) {
	stdIdentityProviders = append(stdIdentityProviders, provider)
	return provider.Init(aCfg)
}

//----------------------------------------------------------------------------------------------------------------------------//

func StdGetIdentity(u string) (identity *Identity, err error) {
	for _, provider := range stdIdentityProviders {
		identity, err = provider.GetIdentity(u)
		if identity != nil || err != nil {
			return
		}
	}

	return nil, nil
}

//----------------------------------------------------------------------------------------------------------------------------//

func StdCheckUser(u string, p string, hashedPassword bool) (identity *Identity, exists bool, err error) {
	for _, provider := range stdIdentityProviders {
		identity, exists, err = provider.Check(u, p, hashedPassword)
		if exists || err != nil {
			return
		}
	}

	return nil, false, nil
}

//----------------------------------------------------------------------------------------------------------------------------//
