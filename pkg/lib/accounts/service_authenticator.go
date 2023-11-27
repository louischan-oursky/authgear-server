package accounts

import (
	"database/sql"
	"errors"

	"github.com/authgear/authgear-server/pkg/api/model"
	"github.com/authgear/authgear-server/pkg/lib/authn/authenticator"
	"github.com/authgear/authgear-server/pkg/lib/infra/db"
	"github.com/authgear/authgear-server/pkg/util/uuid"
)

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

func (s *Service) CreateAuthenticator(info *authenticator.Info) error {
	switch info.Type {
	case model.AuthenticatorTypePassword:
		a := info.Password
		if err := s.PasswordAuthenticators.Create(a); err != nil {
			return err
		}
		*info = *a.ToInfo()
	case model.AuthenticatorTypePasskey:
		a := info.Passkey
		if err := s.PasskeyAuthenticators.Create(a); err != nil {
			return err
		}
		*info = *a.ToInfo()
	case model.AuthenticatorTypeTOTP:
		a := info.TOTP
		if err := s.TOTPAuthenticators.Create(a); err != nil {
			return err
		}
		*info = *a.ToInfo()

	case model.AuthenticatorTypeOOBEmail, model.AuthenticatorTypeOOBSMS:
		a := info.OOBOTP
		if err := s.OOBOTPAuthenticators.Create(a); err != nil {
			return err
		}
		*info = *a.ToInfo()

	default:
		panic("authenticator: unknown authenticator type " + info.Type)
	}

	return nil
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
