package auth

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/alrusov/config"
	"github.com/alrusov/log"
	"github.com/alrusov/misc"
)

//----------------------------------------------------------------------------------------------------------------------------//

type (
	// Handlers --
	Handlers struct {
		sync.RWMutex
		cfg  *config.Listener
		list []Handler
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
		Method   string
		User     string
		UserID   uint64
		UserGUID string
		Groups   []string
		Type     string
		IsAdmin  bool
		Extra    any
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
		cfg: cfg,
	}
}

//----------------------------------------------------------------------------------------------------------------------------//

// Add --
func (hh *Handlers) Add(ah Handler) (err error) {
	hh.Lock()
	defer hh.Unlock()

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
	hh.RLock()
	defer hh.RUnlock()

	return len(hh.list) > 0
}

//----------------------------------------------------------------------------------------------------------------------------//

// WriteAuthRequestHeaders --
func (hh *Handlers) WriteAuthRequestHeaders(w http.ResponseWriter, prefix string, path string) {
	hh.RLock()
	defer hh.RUnlock()

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
			realm := hh.cfg.Auth.Realm
			if realm == "" {
				realm = prefix + path
			}
			s = fmt.Sprintf(`%s realm="%s"`, name, realm)
		}

		w.Header().Add("WWW-Authenticate", s)
	}
}

//----------------------------------------------------------------------------------------------------------------------------//

// Check --
func (hh *Handlers) Check(id uint64, prefix string, path string, permissions misc.BoolMap, w http.ResponseWriter, r *http.Request) (identity *Identity, code int, msg string) {
	hh.RLock()
	defer hh.RUnlock()

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

	// Причину отказа (неизвестный пользователь, неверный пароль, разбор токена) клиенту не отдаём:
	// по ней можно перебирать логины. Методы пишут её в журнал сами, здесь - на уровне DEBUG
	if err != nil {
		Log.Message(log.DEBUG, `[%d] Unauthorised: %s`, id, err)
	}

	code = http.StatusUnauthorized
	msg = "Unauthorised"
	return
}

//----------------------------------------------------------------------------------------------------------------------------//

func (identity *Identity) checkPermissions(permissions misc.BoolMap) bool {
	if identity.IsAdmin {
		// Администратора запреты не касаются
		return true
	}

	if len(permissions) == 0 {
		return false
	}

	// Запрет главнее разрешения всегда, независимо от уровня правила:
	// "!user", "!@group" или "!*" отказывают, даже если пользователь разрешён явно или через другую группу.
	// Доступ есть, если нет ни одного подходящего запрета и есть хотя бы одно подходящее разрешение.

	allowed := false

	check := func(name string) (denied bool) {
		p, exists := permissions[name]
		if !exists {
			return false
		}
		if !p {
			return true
		}
		allowed = true
		return false
	}

	if check(identity.User) {
		return false
	}

	for _, g := range identity.Groups {
		if check("@" + g) {
			return false
		}
	}

	if check("*") {
		return false
	}

	return allowed
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

// PasswordMatch -- проверка пароля пользователя u.
// stored -- хеш из хранилища (см. Hash), p -- переданный пароль или, при hashedPassword, его хеш.
// Пустой хранимый хеш или пустой переданный пароль не совпадают никогда: иначе при hashedPassword
// пользователь без пароля входил бы с пустым p. Хеши сравниваются без учёта регистра и за постоянное время.
func PasswordMatch(stored string, p string, u string, hashedPassword bool) bool {
	if stored == "" || p == "" {
		return false
	}

	if !hashedPassword {
		p = string(Hash([]byte(p), []byte(u)))
	}

	return subtle.ConstantTimeCompare([]byte(strings.ToLower(stored)), []byte(strings.ToLower(p))) == 1
}

//----------------------------------------------------------------------------------------------------------------------------//
