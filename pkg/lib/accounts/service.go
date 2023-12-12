package accounts

import (
	"github.com/authgear/authgear-server/pkg/api/event"
	"github.com/authgear/authgear-server/pkg/api/model"
	"github.com/authgear/authgear-server/pkg/lib/authn/authenticator"
	authenticatorservice "github.com/authgear/authgear-server/pkg/lib/authn/authenticator/service"
	"github.com/authgear/authgear-server/pkg/lib/authn/identity"
	"github.com/authgear/authgear-server/pkg/lib/authn/identity/loginid"
	"github.com/authgear/authgear-server/pkg/lib/authn/otp"
	"github.com/authgear/authgear-server/pkg/lib/authn/user"
	"github.com/authgear/authgear-server/pkg/lib/config"
	"github.com/authgear/authgear-server/pkg/lib/feature/verification"
	"github.com/authgear/authgear-server/pkg/lib/infra/db/appdb"
	"github.com/authgear/authgear-server/pkg/util/accesscontrol"
	"github.com/authgear/authgear-server/pkg/util/clock"
)

//go:generate mockgen -source=service.go -destination=service_mock_test.go -package accounts

type LoginIDIdentities interface {
	New(userID string, loginID identity.LoginIDSpec, options loginid.CheckerOptions) (*identity.LoginID, error)
	Create(i *identity.LoginID) error

	Get(userID, id string) (*identity.LoginID, error)
	GetMany(ids []string) ([]*identity.LoginID, error)
	ListByClaim(name string, value string) ([]*identity.LoginID, error)
	GetByValue(loginIDValue string) ([]*identity.LoginID, error)
	GetByUniqueKey(uniqueKey string) (*identity.LoginID, error)

	WithValue(iden *identity.LoginID, value string, options loginid.CheckerOptions) (*identity.LoginID, error)
	Update(i *identity.LoginID) error
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

	WithUpdate(iden *identity.OAuth, rawProfile map[string]interface{}, claims map[string]interface{}) *identity.OAuth
	Update(i *identity.OAuth) error
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

type PasswordAuthenticators interface {
	New(id string, userID string, password string, isDefault bool, kind string) (*authenticator.Password, error)
	Create(*authenticator.Password) error

	GetMany(ids []string) ([]*authenticator.Password, error)

	WithPassword(a *authenticator.Password, password string) (*authenticator.Password, error)
	AuthenticatePure(a *authenticator.Password, password string) (migrated *authenticator.Password, requireForceChange bool, err error)
	UpdatePassword(*authenticator.Password) error

	Delete(*authenticator.Password) error
}

type PasskeyAuthenticators interface {
	New(
		id string,
		userID string,
		attestationResponse []byte,
		isDefault bool,
		kind string,
	) (*authenticator.Passkey, error)
	Create(*authenticator.Passkey) error

	GetMany(ids []string) ([]*authenticator.Passkey, error)

	AuthenticatePure(a *authenticator.Passkey, assertionResponse []byte) (updated *authenticator.Passkey, err error)
	Update(*authenticator.Passkey) error

	Delete(*authenticator.Passkey) error
}

type TOTPAuthenticators interface {
	New(id string, userID string, displayName string, isDefault bool, kind string) *authenticator.TOTP
	Create(*authenticator.TOTP) error

	GetMany(ids []string) ([]*authenticator.TOTP, error)

	Authenticate(a *authenticator.TOTP, code string) error

	Delete(*authenticator.TOTP) error
}

type OOBOTPAuthenticators interface {
	New(id string, userID string, oobAuthenticatorType model.AuthenticatorType, target string, isDefault bool, kind string) (*authenticator.OOBOTP, error)
	Create(*authenticator.OOBOTP) error

	GetMany(ids []string) ([]*authenticator.OOBOTP, error)

	WithSpec(a *authenticator.OOBOTP, spec *authenticator.OOBOTPSpec) (*authenticator.OOBOTP, error)
	Update(a *authenticator.OOBOTP) error

	Delete(*authenticator.OOBOTP) error
}

type OTPCodes interface {
	VerifyOTP(kind otp.Kind, target string, otp string, opts *otp.VerifyOptions) error
}

type AuthenticatorRateLimits interface {
	Reserve(userID string, typ model.AuthenticatorType) *authenticatorservice.Reservation
	Cancel(r *authenticatorservice.Reservation)
}

type AuthenticatorLockout interface {
	Check(userID string) error
	MakeAttempt(userID string, authenticatorType model.AuthenticatorType) error
}

type VerifiedClaims interface {
	ListByUser(userID string) ([]*verification.Claim, error)
	Create(claim *verification.Claim) error

	Delete(id string) error
}

type Users interface {
	Get(id string) (*user.User, error)
	Create(u *user.User) error
}

type StandardAttributes interface {
	UpdateStandardAttributes0(role accesscontrol.Role, u *user.User, identities []*identity.Info, stdAttrsToUpdate map[string]interface{}) (map[string]interface{}, error)
	PopulateIdentityAwareStandardAttributes0(originalStdAttrs map[string]interface{}, unsortedIdentities []*identity.Info) (map[string]interface{}, bool)
}

type Events interface {
	DispatchEvent(payload event.NonBlockingPayload) error
}

type Service struct {
	Clock       clock.Clock
	SQLBuilder  *appdb.SQLBuilderApp
	SQLExecutor *appdb.SQLExecutor
	AppConfig   *config.AppConfig

	Events Events

	Users              Users
	StandardAttributes StandardAttributes

	IdentityConfig      *config.IdentityConfig
	LoginIDIdentities   LoginIDIdentities
	OAuthIdentities     OAuthIdentities
	AnonymousIdentities AnonymousIdentities
	BiometricIdentities BiometricIdentities
	PasskeyIdentities   PasskeyIdentities
	SIWEIdentities      SIWEIdentities

	PasswordAuthenticators  PasswordAuthenticators
	PasskeyAuthenticators   PasskeyAuthenticators
	TOTPAuthenticators      TOTPAuthenticators
	OOBOTPAuthenticators    OOBOTPAuthenticators
	AuthenticatorRateLimits AuthenticatorRateLimits
	AuthenticatorLockout    AuthenticatorLockout
	OTPCodes                OTPCodes

	VerificationConfig *config.VerificationConfig
	VerifiedClaims     VerifiedClaims
}

func (s *Service) identitiesSlice(identities []*identity.Info, updated []*identity.Info) []*identity.Info {
	var out []*identity.Info
	appended := map[string]struct{}{}

	for _, i := range updated {
		out = append(out, i)
		appended[i.ID] = struct{}{}
	}

	for _, i := range identities {
		_, alreadyAppended := appended[i.ID]
		if !alreadyAppended {
			out = append(out, i)
		}
	}

	return out
}

func (s *Service) authenticatorsSlice(authenticators []*authenticator.Info, updated []*authenticator.Info) []*authenticator.Info {
	var out []*authenticator.Info
	appended := map[string]struct{}{}

	for _, i := range updated {
		out = append(out, i)
		appended[i.ID] = struct{}{}
	}

	for _, i := range authenticators {
		_, alreadyAppended := appended[i.ID]
		if !alreadyAppended {
			out = append(out, i)
		}
	}

	return out
}

func (s *Service) claimsSlice(claims []*verification.Claim, updated []*verification.Claim) []*verification.Claim {
	var out []*verification.Claim
	appended := map[string]struct{}{}

	for _, i := range updated {
		out = append(out, i)
		appended[i.ID] = struct{}{}
	}

	for _, i := range claims {
		_, alreadyAppended := appended[i.ID]
		if !alreadyAppended {
			out = append(out, i)
		}
	}

	return out
}
