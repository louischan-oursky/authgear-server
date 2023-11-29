package accounts

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/authgear/authgear-server/pkg/api"
	"github.com/authgear/authgear-server/pkg/api/apierrors"
	"github.com/authgear/authgear-server/pkg/api/event/nonblocking"
	"github.com/authgear/authgear-server/pkg/api/model"
	"github.com/authgear/authgear-server/pkg/lib/authn"
	"github.com/authgear/authgear-server/pkg/lib/authn/authenticator"
	"github.com/authgear/authgear-server/pkg/lib/authn/otp"
	"github.com/authgear/authgear-server/pkg/lib/infra/db"
	"github.com/authgear/authgear-server/pkg/util/errorutil"
	"github.com/authgear/authgear-server/pkg/util/uuid"
)

type VerifyAuthenticatorOptions struct {
	UserID             string
	Stage              authn.AuthenticationStage
	AuthenticatorType  model.AuthenticatorType
	AuthenticationType authn.AuthenticationType

	OOBChannel model.AuthenticatorOOBChannel
}

type VerifyAuthenticatorResult struct {
	UsedAuthenticator    *authenticator.Info
	UpdatedAuthenticator *authenticator.Info
	RequireForceChange   bool
}

type ResetPrimaryPasswordResult struct {
	MaybeUpdatedAuthenticator *authenticator.Info
	MaybeNewAuthenticator     *authenticator.Info
	RemovedAuthenticators     []*authenticator.Info
}

func (s *Service) NewAuthenticator(spec *authenticator.Spec) (*authenticator.Info, error) {
	authenticatorID := uuid.New()

	switch spec.Type {
	case model.AuthenticatorTypePassword:
		plainPassword := spec.Password.PlainPassword
		p, err := s.PasswordAuthenticators.New(authenticatorID, spec.UserID, plainPassword, spec.IsDefault, string(spec.Kind))
		if err != nil {
			return nil, err
		}
		return p.ToInfo(), nil

	case model.AuthenticatorTypePasskey:
		attestationResponse := spec.Passkey.AttestationResponse

		p, err := s.PasskeyAuthenticators.New(
			authenticatorID,
			spec.UserID,
			attestationResponse,
			spec.IsDefault,
			string(spec.Kind),
		)
		if err != nil {
			return nil, err
		}
		return p.ToInfo(), nil

	case model.AuthenticatorTypeTOTP:
		displayName := spec.TOTP.DisplayName
		t := s.TOTPAuthenticators.New(authenticatorID, spec.UserID, displayName, spec.IsDefault, string(spec.Kind))
		return t.ToInfo(), nil

	case model.AuthenticatorTypeOOBEmail:
		email := spec.OOBOTP.Email
		o, err := s.OOBOTPAuthenticators.New(authenticatorID, spec.UserID, model.AuthenticatorTypeOOBEmail, email, spec.IsDefault, string(spec.Kind))
		if err != nil {
			return nil, err
		}

		return o.ToInfo(), nil
	case model.AuthenticatorTypeOOBSMS:
		phone := spec.OOBOTP.Phone
		o, err := s.OOBOTPAuthenticators.New(authenticatorID, spec.UserID, model.AuthenticatorTypeOOBSMS, phone, spec.IsDefault, string(spec.Kind))
		if err != nil {
			return nil, err
		}
		return o.ToInfo(), nil

	}

	panic("authenticator: unknown authenticator type " + spec.Type)
}

func (s *Service) ListAuthenticatorsOfUser(userID string) ([]*authenticator.Info, error) {
	refs, err := s.listAuthenticatorRefsOfUser(userID)
	if err != nil {
		return nil, err
	}

	refsByType := map[model.AuthenticatorType]([]*authenticator.Ref){}
	for _, ref := range refs {
		arr := refsByType[ref.Type]
		arr = append(arr, ref)
		refsByType[ref.Type] = arr
	}

	extractIDs := func(authenticatorRefs []*authenticator.Ref) []string {
		ids := []string{}
		for _, r := range authenticatorRefs {
			ids = append(ids, r.ID)
		}
		return ids
	}

	infos := []*authenticator.Info{}

	// password
	if passwordRefs, ok := refsByType[model.AuthenticatorTypePassword]; ok && len(passwordRefs) > 0 {
		passwords, err := s.PasswordAuthenticators.GetMany(extractIDs(passwordRefs))
		if err != nil {
			return nil, err
		}
		for _, i := range passwords {
			infos = append(infos, i.ToInfo())
		}
	}

	// passkey
	if passkeyRefs, ok := refsByType[model.AuthenticatorTypePasskey]; ok && len(passkeyRefs) > 0 {
		passkeys, err := s.PasskeyAuthenticators.GetMany(extractIDs(passkeyRefs))
		if err != nil {
			return nil, err
		}
		for _, i := range passkeys {
			infos = append(infos, i.ToInfo())
		}
	}

	// totp
	if totpRefs, ok := refsByType[model.AuthenticatorTypeTOTP]; ok && len(totpRefs) > 0 {
		totps, err := s.TOTPAuthenticators.GetMany(extractIDs(totpRefs))
		if err != nil {
			return nil, err
		}
		for _, i := range totps {
			infos = append(infos, i.ToInfo())
		}
	}

	// oobotp
	oobotpRefs := []*authenticator.Ref{}
	if oobotpSMSRefs, ok := refsByType[model.AuthenticatorTypeOOBSMS]; ok && len(oobotpSMSRefs) > 0 {
		oobotpRefs = append(oobotpRefs, oobotpSMSRefs...)
	}
	if oobotpEmailRefs, ok := refsByType[model.AuthenticatorTypeOOBEmail]; ok && len(oobotpEmailRefs) > 0 {
		oobotpRefs = append(oobotpRefs, oobotpEmailRefs...)
	}
	if len(oobotpRefs) > 0 {
		oobotps, err := s.OOBOTPAuthenticators.GetMany(extractIDs(oobotpRefs))
		if err != nil {
			return nil, err
		}
		for _, i := range oobotps {
			infos = append(infos, i.ToInfo())
		}
	}

	return infos, nil
}

func (s *Service) UpdateAuthenticatorWithSpec(info *authenticator.Info, spec *authenticator.Spec) (bool, *authenticator.Info, error) {
	changed := false
	switch info.Type {
	case model.AuthenticatorTypePassword:
		a := info.Password
		plainPassword := spec.Password.PlainPassword
		newAuth, err := s.PasswordAuthenticators.WithPassword(a, plainPassword)
		if err != nil {
			return false, nil, err
		}
		changed = (newAuth != a)
		return changed, newAuth.ToInfo(), nil
	case model.AuthenticatorTypeOOBEmail:
		fallthrough
	case model.AuthenticatorTypeOOBSMS:
		a := info.OOBOTP
		newAuth, err := s.OOBOTPAuthenticators.WithSpec(a, spec.OOBOTP)
		if err != nil {
			return false, nil, err
		}
		changed = (newAuth != a)
		return changed, newAuth.ToInfo(), nil
	}

	panic("authenticator: update authenticator is not supported for type " + info.Type)
}

func (s *Service) VerifyAuthenticatorsWithSpec(infos []*authenticator.Info, spec *authenticator.Spec, options *VerifyAuthenticatorOptions) (*VerifyAuthenticatorResult, error) {
	result, err := s.verifyAuthenticatorsWithSpec(infos, spec, options)
	if errors.Is(err, api.ErrInvalidCredentials) {
		eventerr := s.dispatchAuthenticationFailedEvent(
			options.UserID,
			options.Stage,
			options.AuthenticationType,
		)
		if eventerr != nil {
			return nil, eventerr
		}
		err = s.addAuthenticationTypeToError(err, options.AuthenticationType)
		return nil, err
	} else if err != nil {
		return nil, err
	}

	return result, nil
}

func (s *Service) ResetPrimaryPassword(infos []*authenticator.Info, state *otp.State, newPassword string) (*ResetPrimaryPasswordResult, error) {
	passwords := authenticator.ApplyFilters(
		infos,
		authenticator.KeepType(model.AuthenticatorTypePassword),
		authenticator.KeepKind(authenticator.KindPrimary),
	)

	switch {
	case len(passwords) == 1:
		// The normal case: the user has 1 primary password
		changed, updated, err := s.UpdateAuthenticatorWithSpec(passwords[0], &authenticator.Spec{
			Password: &authenticator.PasswordSpec{
				PlainPassword: newPassword,
			},
		})
		if err != nil {
			return nil, err
		}

		result := &ResetPrimaryPasswordResult{}
		if changed {
			result.MaybeUpdatedAuthenticator = updated
		}
		return result, nil
	default:
		// The special case: the user either has no primary password or
		// more than 1 primary passwords.
		// We delete the existing primary passwords and then create a new one.
		isDefault := false
		for _, p := range passwords {
			if p.IsDefault {
				isDefault = true
			}
		}

		newPasswordAuthenticator, err := s.NewAuthenticator(&authenticator.Spec{
			Type:      model.AuthenticatorTypePassword,
			Kind:      authenticator.KindPrimary,
			UserID:    state.UserID,
			IsDefault: isDefault,
			Password: &authenticator.PasswordSpec{
				PlainPassword: newPassword,
			},
		})
		if err != nil {
			return nil, err
		}

		result := &ResetPrimaryPasswordResult{}
		result.MaybeNewAuthenticator = newPasswordAuthenticator
		result.RemovedAuthenticators = passwords
		return result, nil
	}
}

func (s *Service) dispatchAuthenticationFailedEvent(
	userID string,
	stage authn.AuthenticationStage,
	authenticationType authn.AuthenticationType,
) error {
	return s.Events.DispatchErrorEvent(&nonblocking.AuthenticationFailedEventPayload{
		UserRef: model.UserRef{
			Meta: model.Meta{
				ID: userID,
			},
		},
		AuthenticationStage: string(stage),
		AuthenticationType:  string(authenticationType),
	})
}

func (c *Service) addAuthenticationTypeToError(err error, authnType authn.AuthenticationType) error {
	d := errorutil.Details{
		"AuthenticationType": apierrors.APIErrorDetail.Value(authnType),
	}
	newe := errorutil.WithDetails(err, d)
	return newe
}

func (s *Service) verifyAuthenticatorsWithSpec(infos []*authenticator.Info, spec *authenticator.Spec, options *VerifyAuthenticatorOptions) (*VerifyAuthenticatorResult, error) {
	r := s.AuthenticatorRateLimits.Reserve(options.UserID, options.AuthenticatorType)
	defer s.AuthenticatorRateLimits.Cancel(r)

	if err := r.Error(); err != nil {
		return nil, err
	}

	err := s.AuthenticatorLockout.Check(options.UserID)
	if err != nil {
		return nil, err
	}

	var used *authenticator.Info
	var updated *authenticator.Info
	var requireForceChange bool
	for _, thisInfo := range infos {
		if thisInfo.UserID != options.UserID || thisInfo.Type != options.AuthenticatorType {
			// Ensure all authenticators are in same type of the same user
			err := fmt.Errorf("only authenticators with same type of same user can be verified together")
			return nil, err
		}

		var err error
		updated, requireForceChange, err = s.verifyAuthenticatorWithSpec(thisInfo, spec, options)
		if errors.Is(err, api.ErrInvalidCredentials) {
			continue
		}

		// unexpected errors or no error
		// For both cases we should break the loop and return
		if err == nil {
			used = thisInfo
		}
		break
	}

	switch {
	case used == nil && err == nil:
		// If we reach here, it means infos is empty.
		// Here is one case that infos is empty.
		// The end-user remove their passkey in Authgear, but keep the passkey in their browser.
		// Authgear will see an passkey that it does not know.
		err = api.ErrInvalidCredentials
	case used != nil && err == nil:
		// Authenticated.
		break
	case used == nil && err != nil:
		// Some error.
		break
	default:
		panic(fmt.Errorf("unexpected post condition: used != nil && err != nil"))
	}

	// If error is ErrInvalidCredentials, consume rate limit token and increment lockout attempt
	if errors.Is(err, api.ErrInvalidCredentials) {
		r.Consume()
		lockErr := s.AuthenticatorLockout.MakeAttempt(options.UserID, options.AuthenticatorType)
		if lockErr != nil {
			err = errors.Join(lockErr, err)
			return nil, err
		}
		return nil, err
	} else if err != nil {
		return nil, err
	}

	return &VerifyAuthenticatorResult{
		UsedAuthenticator:    used,
		UpdatedAuthenticator: updated,
		RequireForceChange:   requireForceChange,
	}, nil
}

func (s *Service) verifyAuthenticatorWithSpec(info *authenticator.Info, spec *authenticator.Spec, options *VerifyAuthenticatorOptions) (updated *authenticator.Info, requireForceChange bool, err error) {
	switch info.Type {
	case model.AuthenticatorTypePassword:
		plainPassword := spec.Password.PlainPassword
		a := info.Password
		var migrated *authenticator.Password
		migrated, requireForceChange, err = s.PasswordAuthenticators.AuthenticatePure(a, plainPassword)
		if err != nil {
			err = api.ErrInvalidCredentials
			return
		}
		if migrated != nil {
			updated = migrated.ToInfo()
		}
		return
	case model.AuthenticatorTypePasskey:
		assertionResponse := spec.Passkey.AssertionResponse
		a := info.Passkey
		var updatedPasskey *authenticator.Passkey
		updatedPasskey, err = s.PasskeyAuthenticators.AuthenticatePure(a, assertionResponse)
		if err != nil {
			err = api.ErrInvalidCredentials
			return
		}
		if updatedPasskey != nil {
			updated = updatedPasskey.ToInfo()
		}
		return
	case model.AuthenticatorTypeTOTP:
		code := spec.TOTP.Code
		a := info.TOTP
		if s.TOTPAuthenticators.Authenticate(a, code) != nil {
			err = api.ErrInvalidCredentials
			return
		}
		return
	case model.AuthenticatorTypeOOBEmail, model.AuthenticatorTypeOOBSMS:
		var channel model.AuthenticatorOOBChannel
		if options.OOBChannel != "" {
			channel = options.OOBChannel
		} else {
			switch info.Type {
			case model.AuthenticatorTypeOOBEmail:
				channel = model.AuthenticatorOOBChannelEmail
			case model.AuthenticatorTypeOOBSMS:
				channel = model.AuthenticatorOOBChannelSMS
			}
		}
		kind := otp.KindOOBOTP(s.AppConfig, channel)

		code := spec.OOBOTP.Code
		a := info.OOBOTP
		err = s.OTPCodes.VerifyOTP(kind, a.ToTarget(), code, &otp.VerifyOptions{
			UserID: options.UserID,
		})
		if apierrors.IsKind(err, otp.InvalidOTPCode) {
			err = api.ErrInvalidCredentials
			return
		} else if err != nil {
			return
		}
		return
	}

	panic("authenticator: unhandled authenticator type " + info.Type)
}

func (s *Service) scanAuthenticatorRef(scanner db.Scanner) (*authenticator.Ref, error) {
	ref := &authenticator.Ref{}
	err := scanner.Scan(
		&ref.ID,
		&ref.Type,
		&ref.UserID,
		&ref.CreatedAt,
		&ref.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, authenticator.ErrAuthenticatorNotFound
	} else if err != nil {
		return nil, err
	}

	return ref, nil
}

func (s *Service) listAuthenticatorRefsOfUser(userID string) ([]*authenticator.Ref, error) {
	builder := s.SQLBuilder.
		Select("id", "type", "user_id", "created_at", "updated_at").
		Where("user_id = ?", userID).
		From(s.SQLBuilder.TableName("_auth_authenticator"))

	rows, err := s.SQLExecutor.QueryWith(builder)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var refs []*authenticator.Ref
	for rows.Next() {
		var ref *authenticator.Ref
		ref, err = s.scanAuthenticatorRef(rows)
		if err != nil {
			return nil, err
		}
		refs = append(refs, ref)
	}

	return refs, nil
}
