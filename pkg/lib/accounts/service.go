package accounts

import (
	"github.com/authgear/authgear-server/pkg/lib/authn/identity"
	"github.com/authgear/authgear-server/pkg/lib/authn/identity/loginid"
	"github.com/authgear/authgear-server/pkg/lib/config"
	"github.com/authgear/authgear-server/pkg/lib/infra/db/appdb"
)

type LoginIDIdentities interface {
	New(userID string, loginID identity.LoginIDSpec, options loginid.CheckerOptions) (*identity.LoginID, error)
	Create(i *identity.LoginID) error

	Get(userID, id string) (*identity.LoginID, error)
	GetMany(ids []string) ([]*identity.LoginID, error)
	ListByClaim(name string, value string) ([]*identity.LoginID, error)
	GetByValue(loginIDValue string) ([]*identity.LoginID, error)
	GetByUniqueKey(uniqueKey string) (*identity.LoginID, error)
}

type OAuthIdentities interface {
	New(
		userID string,
		provider config.ProviderID,
		subjectID string,
		profile map[string]interface{},
		claims map[string]interface{},
	) *identity.OAuth
	Create(i *identity.OAuth) error

	Get(userID, id string) (*identity.OAuth, error)
	GetMany(ids []string) ([]*identity.OAuth, error)
	ListByClaim(name string, value string) ([]*identity.OAuth, error)
	GetByProviderSubject(provider config.ProviderID, subjectID string) (*identity.OAuth, error)
}

type AnonymousIdentities interface {
	New(userID string, keyID string, key []byte) *identity.Anonymous
	Create(i *identity.Anonymous) error

	Get(userID, id string) (*identity.Anonymous, error)
	GetMany(ids []string) ([]*identity.Anonymous, error)
	GetByKeyID(keyID string) (*identity.Anonymous, error)
}

type BiometricIdentities interface {
	New(userID string, keyID string, key []byte, deviceInfo map[string]interface{}) *identity.Biometric
	Create(i *identity.Biometric) error

	Get(userID, id string) (*identity.Biometric, error)
	GetMany(ids []string) ([]*identity.Biometric, error)
	GetByKeyID(keyID string) (*identity.Biometric, error)
}

type PasskeyIdentities interface {
	New(userID string, attestationResponse []byte) (*identity.Passkey, error)
	Create(i *identity.Passkey) error

	Get(userID, id string) (*identity.Passkey, error)
	GetMany(ids []string) ([]*identity.Passkey, error)
	GetByAssertionResponse(assertionResponse []byte) (*identity.Passkey, error)
}

type SIWEIdentities interface {
	New(userID string, msg string, signature string) (*identity.SIWE, error)
	Create(i *identity.SIWE) error

	Get(userID, id string) (*identity.SIWE, error)
	GetMany(ids []string) ([]*identity.SIWE, error)
	GetByMessage(msg string, signature string) (*identity.SIWE, error)
}

type Service struct {
	SQLBuilder  *appdb.SQLBuilderApp
	SQLExecutor *appdb.SQLExecutor

	LoginIDIdentities   LoginIDIdentities
	OAuthIdentities     OAuthIdentities
	AnonymousIdentities AnonymousIdentities
	BiometricIdentities BiometricIdentities
	PasskeyIdentities   PasskeyIdentities
	SIWEIdentities      SIWEIdentities
}
