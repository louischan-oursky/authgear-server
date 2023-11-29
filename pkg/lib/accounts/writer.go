package accounts

import (
	"encoding/json"

	"github.com/authgear/authgear-server/pkg/api/model"
	"github.com/authgear/authgear-server/pkg/lib/authn/authenticator"
	"github.com/authgear/authgear-server/pkg/lib/authn/identity"
	"github.com/authgear/authgear-server/pkg/lib/authn/user"
	"github.com/authgear/authgear-server/pkg/lib/feature/verification"
	"github.com/authgear/authgear-server/pkg/lib/infra/db/appdb"
)

type Writer struct {
	SQLBuilder  *appdb.SQLBuilderApp
	SQLExecutor *appdb.SQLExecutor

	Users Users

	LoginIDIdentities   LoginIDIdentities
	OAuthIdentities     OAuthIdentities
	AnonymousIdentities AnonymousIdentities
	BiometricIdentities BiometricIdentities
	PasskeyIdentities   PasskeyIdentities
	SIWEIdentities      SIWEIdentities

	PasswordAuthenticators PasswordAuthenticators
	PasskeyAuthenticators  PasskeyAuthenticators
	TOTPAuthenticators     TOTPAuthenticators
	OOBOTPAuthenticators   OOBOTPAuthenticators

	VerifiedClaims VerifiedClaims
}

func (w *Writer) CreateUser(u *user.User) error {
	return w.Users.Create(u)
}

func (w *Writer) UpdateUser(u *user.User) error {
	stdAttrsBytes, err := json.Marshal(u.StandardAttributes)
	if err != nil {
		return err
	}

	customAttrsBytes, err := json.Marshal(u.CustomAttributes)
	if err != nil {
		return err
	}

	builder := w.SQLBuilder.
		Update(w.SQLBuilder.TableName("_auth_user")).
		Set("is_disabled", u.IsDisabled).
		Set("disable_reason", u.DisableReason).
		Set("is_deactivated", u.IsDeactivated).
		Set("delete_at", u.DeleteAt).
		Set("is_anonymized", u.IsAnonymized).
		Set("anonymize_at", u.AnonymizeAt).
		Set("last_login_at", u.LessRecentLoginAt).
		Set("login_at", u.MostRecentLoginAt).
		Set("standard_attributes", stdAttrsBytes).
		Set("custom_attributes", customAttrsBytes).
		Set("updated_at", u.UpdatedAt).
		Where("id = ?", u.ID)

	_, err = w.SQLExecutor.ExecWith(builder)
	if err != nil {
		return err
	}

	return nil
}

func (w *Writer) CreateAuthenticator(info *authenticator.Info) error {
	switch info.Type {
	case model.AuthenticatorTypePassword:
		a := info.Password
		if err := w.PasswordAuthenticators.Create(a); err != nil {
			return err
		}
	case model.AuthenticatorTypePasskey:
		a := info.Passkey
		if err := w.PasskeyAuthenticators.Create(a); err != nil {
			return err
		}
	case model.AuthenticatorTypeTOTP:
		a := info.TOTP
		if err := w.TOTPAuthenticators.Create(a); err != nil {
			return err
		}
	case model.AuthenticatorTypeOOBEmail, model.AuthenticatorTypeOOBSMS:
		a := info.OOBOTP
		if err := w.OOBOTPAuthenticators.Create(a); err != nil {
			return err
		}
	default:
		panic("authenticator: unknown authenticator type " + info.Type)
	}

	return nil
}

func (w *Writer) UpdateAuthenticator(info *authenticator.Info) error {
	switch info.Type {
	case model.AuthenticatorTypePassword:
		a := info.Password
		if err := w.PasswordAuthenticators.UpdatePassword(a); err != nil {
			return err
		}
	case model.AuthenticatorTypePasskey:
		a := info.Passkey
		if err := w.PasskeyAuthenticators.Update(a); err != nil {
			return err
		}
	case model.AuthenticatorTypeOOBEmail:
		a := info.OOBOTP
		if err := w.OOBOTPAuthenticators.Update(a); err != nil {
			return err
		}
	case model.AuthenticatorTypeOOBSMS:
		a := info.OOBOTP
		if err := w.OOBOTPAuthenticators.Update(a); err != nil {
			return err
		}
	default:
		panic("authenticator: unknown authenticator type for update" + info.Type)
	}

	return nil
}

func (w *Writer) DeleteAuthenticator(info *authenticator.Info) error {
	switch info.Type {
	case model.AuthenticatorTypePassword:
		a := info.Password
		if err := w.PasswordAuthenticators.Delete(a); err != nil {
			return err
		}
	case model.AuthenticatorTypePasskey:
		a := info.Passkey
		if err := w.PasskeyAuthenticators.Delete(a); err != nil {
			return err
		}
	case model.AuthenticatorTypeTOTP:
		a := info.TOTP
		if err := w.TOTPAuthenticators.Delete(a); err != nil {
			return err
		}
	case model.AuthenticatorTypeOOBEmail, model.AuthenticatorTypeOOBSMS:
		a := info.OOBOTP
		if err := w.OOBOTPAuthenticators.Delete(a); err != nil {
			return err
		}
	default:
		panic("authenticator: delete authenticator is not supported yet for type " + info.Type)
	}

	return nil
}

func (w *Writer) CreateIdentity(info *identity.Info) error {
	switch info.Type {
	case model.IdentityTypeLoginID:
		i := info.LoginID
		if err := w.LoginIDIdentities.Create(i); err != nil {
			return err
		}
	case model.IdentityTypeOAuth:
		i := info.OAuth
		if err := w.OAuthIdentities.Create(i); err != nil {
			return err
		}
	case model.IdentityTypeAnonymous:
		i := info.Anonymous
		if err := w.AnonymousIdentities.Create(i); err != nil {
			return err
		}
	case model.IdentityTypeBiometric:
		i := info.Biometric
		if err := w.BiometricIdentities.Create(i); err != nil {
			return err
		}
	case model.IdentityTypePasskey:
		i := info.Passkey
		if err := w.PasskeyIdentities.Create(i); err != nil {
			return err
		}
	case model.IdentityTypeSIWE:
		i := info.SIWE
		if err := w.SIWEIdentities.Create(i); err != nil {
			return err
		}
	default:
		panic("identity: unknown identity type " + info.Type)
	}
	return nil
}

func (w *Writer) UpdateIdentity(info *identity.Info) error {
	switch info.Type {
	case model.IdentityTypeLoginID:
		i := info.LoginID
		if err := w.LoginIDIdentities.Update(i); err != nil {
			return err
		}
	case model.IdentityTypeOAuth:
		i := info.OAuth
		if err := w.OAuthIdentities.Update(i); err != nil {
			return err
		}
	case model.IdentityTypeAnonymous:
		panic("identity: update no support for identity type " + info.Type)
	case model.IdentityTypeBiometric:
		panic("identity: update no support for identity type " + info.Type)
	case model.IdentityTypePasskey:
		panic("identity: update no support for identity type " + info.Type)
	case model.IdentityTypeSIWE:
		panic("identity: update no support for identity type " + info.Type)
	default:
		panic("identity: unknown identity type " + info.Type)
	}

	return nil
}

func (w *Writer) CreateVerifiedClaim(claim *verification.Claim) error {
	return w.VerifiedClaims.Create(claim)
}

func (w *Writer) DeleteVerifiedClaim(claim *verification.Claim) error {
	return w.VerifiedClaims.Delete(claim.ID)
}
