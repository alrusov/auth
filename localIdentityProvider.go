package auth

import "github.com/alrusov/config"

//----------------------------------------------------------------------------------------------------------------------------//

type (
	LocalIdentityProvider struct {
		aCfg *config.Auth
	}
)

//----------------------------------------------------------------------------------------------------------------------------//

func (provider *LocalIdentityProvider) Init(aCfg *config.Auth) (err error) {
	provider.aCfg = aCfg
	return
}

//----------------------------------------------------------------------------------------------------------------------------//

func (provider *LocalIdentityProvider) GetIdentity(u string) (identity *Identity, err error) {
	userDef, exists := provider.aCfg.Users[u]
	if !exists {
		return nil, nil
	}

	return &Identity{
			User:   u,
			Groups: userDef.Groups,
		},
		nil
}

//----------------------------------------------------------------------------------------------------------------------------//

func (provider *LocalIdentityProvider) Check(u string, p string, hashedPassword bool) (identity *Identity, exists bool, err error) {
	userDef, exists := provider.aCfg.Users[u]
	if !exists {
		return nil, false, nil
	}

	if hashedPassword {
		if userDef.Password != p {
			return nil, true, nil
		}
	} else {
		if userDef.Password != string(Hash([]byte(p), []byte(u))) {
			return nil, true, nil
		}
	}

	return &Identity{
			User:   u,
			Groups: userDef.Groups,
		},
		true,
		nil
}

//----------------------------------------------------------------------------------------------------------------------------//
