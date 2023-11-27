package accounts

import (
	"errors"
	"fmt"

	"github.com/authgear/authgear-server/pkg/api/model"
	"github.com/authgear/authgear-server/pkg/lib/authn/identity"
	"github.com/authgear/authgear-server/pkg/lib/authn/identity/loginid"
	"github.com/authgear/authgear-server/pkg/lib/infra/db"
)

func (s *Service) GetIdentityByID(id string) (*identity.Info, error) {
	ref, err := s.getIdentityRefByID(id)
	if err != nil {
		return nil, err
	}
	switch ref.Type {
	case model.IdentityTypeLoginID:
		l, err := s.LoginIDIdentities.Get(ref.UserID, id)
		if err != nil {
			return nil, err
		}
		return l.ToInfo(), nil
	case model.IdentityTypeOAuth:
		o, err := s.OAuthIdentities.Get(ref.UserID, id)
		if err != nil {
			return nil, err
		}
		return o.ToInfo(), nil
	case model.IdentityTypeAnonymous:
		a, err := s.AnonymousIdentities.Get(ref.UserID, id)
		if err != nil {
			return nil, err
		}
		return a.ToInfo(), nil
	case model.IdentityTypeBiometric:
		b, err := s.BiometricIdentities.Get(ref.UserID, id)
		if err != nil {
			return nil, err
		}
		return b.ToInfo(), nil
	case model.IdentityTypePasskey:
		p, err := s.PasskeyIdentities.Get(ref.UserID, id)
		if err != nil {
			return nil, err
		}
		return p.ToInfo(), nil
	case model.IdentityTypeSIWE:
		s, err := s.SIWEIdentities.Get(ref.UserID, id)
		if err != nil {
			return nil, err
		}
		return s.ToInfo(), nil
	}

	panic("identity: unknown identity type " + ref.Type)
}

func (s *Service) SearchIdentities(spec *identity.Spec) (exactMatch *identity.Info, otherMatches []*identity.Info, err error) {
	exactMatch, err = s.getIdentityBySpec(spec)
	// The simplest case is the exact match case.
	if err == nil {
		return
	}

	// Any error other than identity.ErrIdentityNotFound
	if err != nil && !errors.Is(err, identity.ErrIdentityNotFound) {
		return
	}

	// Do not consider identity.ErrIdentityNotFound as error.
	err = nil

	claimsToSearch := make(map[string]interface{})

	// Otherwise we have to search.
	switch spec.Type {
	case model.IdentityTypeLoginID:
		// For login ID, we treat the login ID value as email, phone_number and preferred_username.
		loginID := spec.LoginID.Value
		claimsToSearch[string(model.ClaimEmail)] = loginID
		claimsToSearch[string(model.ClaimPhoneNumber)] = loginID
		claimsToSearch[string(model.ClaimPreferredUsername)] = loginID
	case model.IdentityTypeOAuth:
		if spec.OAuth.StandardClaims != nil {
			claimsToSearch = spec.OAuth.StandardClaims
		}
	default:
		break
	}

	for name, value := range claimsToSearch {
		str, ok := value.(string)
		if !ok {
			continue
		}
		switch name {
		case string(model.ClaimEmail),
			string(model.ClaimPhoneNumber),
			string(model.ClaimPreferredUsername):

			var loginIDs []*identity.LoginID
			loginIDs, err = s.LoginIDIdentities.ListByClaim(name, str)
			if err != nil {
				return
			}

			for _, loginID := range loginIDs {
				otherMatches = append(otherMatches, loginID.ToInfo())
			}

			var oauths []*identity.OAuth
			oauths, err = s.OAuthIdentities.ListByClaim(name, str)
			if err != nil {
				return
			}

			for _, o := range oauths {
				otherMatches = append(otherMatches, o.ToInfo())
			}

		}
	}

	return
}

func (s *Service) ListIdentitiesByClaim(name string, value string) ([]*identity.Info, error) {
	var infos []*identity.Info

	// login id
	lis, err := s.LoginIDIdentities.ListByClaim(name, value)
	if err != nil {
		return nil, err
	}
	for _, i := range lis {
		infos = append(infos, i.ToInfo())
	}

	// oauth
	ois, err := s.OAuthIdentities.ListByClaim(name, value)
	if err != nil {
		return nil, err
	}
	for _, i := range ois {
		infos = append(infos, i.ToInfo())
	}

	return infos, nil
}

func (s *Service) ListIdentitiesOfUser(userID string) ([]*identity.Info, error) {
	refs, err := s.listIdentityRefsOfUser(userID)
	if err != nil {
		return nil, err
	}

	refsByType := map[model.IdentityType]([]*model.IdentityRef){}
	for _, ref := range refs {
		arr := refsByType[ref.Type]
		arr = append(arr, ref)
		refsByType[ref.Type] = arr
	}

	extractIDs := func(idRefs []*model.IdentityRef) []string {
		ids := []string{}
		for _, idRef := range idRefs {
			ids = append(ids, idRef.ID)
		}
		return ids
	}

	infos := []*identity.Info{}

	// login id
	if loginIDRefs, ok := refsByType[model.IdentityTypeLoginID]; ok && len(loginIDRefs) > 0 {
		loginIDs, err := s.LoginIDIdentities.GetMany(extractIDs(loginIDRefs))
		if err != nil {
			return nil, err
		}
		for _, i := range loginIDs {
			infos = append(infos, i.ToInfo())
		}
	}

	// oauth
	if oauthRefs, ok := refsByType[model.IdentityTypeOAuth]; ok && len(oauthRefs) > 0 {
		oauthIdens, err := s.OAuthIdentities.GetMany(extractIDs(oauthRefs))
		if err != nil {
			return nil, err
		}
		for _, i := range oauthIdens {
			infos = append(infos, i.ToInfo())
		}
	}

	// anonymous
	if anonymousRefs, ok := refsByType[model.IdentityTypeAnonymous]; ok && len(anonymousRefs) > 0 {
		anonymousIdens, err := s.AnonymousIdentities.GetMany(extractIDs(anonymousRefs))
		if err != nil {
			return nil, err
		}
		for _, i := range anonymousIdens {
			infos = append(infos, i.ToInfo())
		}
	}

	// biometric
	if biometricRefs, ok := refsByType[model.IdentityTypeBiometric]; ok && len(biometricRefs) > 0 {
		biometricIdens, err := s.BiometricIdentities.GetMany(extractIDs(biometricRefs))
		if err != nil {
			return nil, err
		}
		for _, i := range biometricIdens {
			infos = append(infos, i.ToInfo())
		}
	}

	// passkey
	if passkeyRefs, ok := refsByType[model.IdentityTypePasskey]; ok && len(passkeyRefs) > 0 {
		passkeyIdens, err := s.PasskeyIdentities.GetMany(extractIDs(passkeyRefs))
		if err != nil {
			return nil, err
		}
		for _, i := range passkeyIdens {
			infos = append(infos, i.ToInfo())
		}
	}

	// siwe
	if siweRefs, ok := refsByType[model.IdentityTypeSIWE]; ok && len(siweRefs) > 0 {
		siweIdens, err := s.SIWEIdentities.GetMany(extractIDs(siweRefs))
		if err != nil {
			return nil, err
		}
		for _, i := range siweIdens {
			infos = append(infos, i.ToInfo())
		}
	}

	return infos, nil
}

func (s *Service) NewIdentity(userID string, spec *identity.Spec) (*identity.Info, error) {
	switch spec.Type {
	case model.IdentityTypeLoginID:
		l, err := s.LoginIDIdentities.New(userID, *spec.LoginID, loginid.CheckerOptions{
			// The use case of NewIdentity does not bypass.
			EmailByPassBlocklistAllowlist: false,
		})
		if err != nil {
			return nil, err
		}
		return l.ToInfo(), nil
	case model.IdentityTypeOAuth:
		providerID := spec.OAuth.ProviderID
		subjectID := spec.OAuth.SubjectID
		rawProfile := spec.OAuth.RawProfile
		standardClaims := spec.OAuth.StandardClaims
		o := s.OAuthIdentities.New(userID, providerID, subjectID, rawProfile, standardClaims)
		return o.ToInfo(), nil
	case model.IdentityTypeAnonymous:
		keyID := spec.Anonymous.KeyID
		key := spec.Anonymous.Key
		a := s.AnonymousIdentities.New(userID, keyID, []byte(key))
		return a.ToInfo(), nil
	case model.IdentityTypeBiometric:
		keyID := spec.Biometric.KeyID
		key := spec.Biometric.Key
		deviceInfo := spec.Biometric.DeviceInfo
		b := s.BiometricIdentities.New(userID, keyID, []byte(key), deviceInfo)
		return b.ToInfo(), nil
	case model.IdentityTypePasskey:
		attestationResponse := spec.Passkey.AttestationResponse
		p, err := s.PasskeyIdentities.New(userID, attestationResponse)
		if err != nil {
			return nil, err
		}
		return p.ToInfo(), nil
	case model.IdentityTypeSIWE:
		message := spec.SIWE.Message
		signature := spec.SIWE.Signature
		e, err := s.SIWEIdentities.New(userID, message, signature)
		if err != nil {
			return nil, err
		}
		return e.ToInfo(), nil
	}

	panic("identity: unknown identity type " + spec.Type)
}

func (s *Service) FindDuplicatedIdentity(info *identity.Info) (duplicate *identity.Info, err error) {
	// There are two ways to check duplicate.
	// 1. Check duplicate by considering standard attributes.
	// 2. Check duplicate by considering type-specific unique key.
	// Only LoginID and OAuth has identity aware standard attributes and unique key.

	// 1. Check duplicate by considering standard attributes.
	claims := info.IdentityAwareStandardClaims()
	for name, value := range claims {
		var loginIDs []*identity.LoginID
		loginIDs, err = s.LoginIDIdentities.ListByClaim(string(name), value)
		if err != nil {
			return nil, err
		}

		for _, i := range loginIDs {
			if i.UserID == info.UserID {
				continue
			}
			duplicate = i.ToInfo()
			err = identity.ErrIdentityAlreadyExists
			return
		}

		var oauths []*identity.OAuth
		oauths, err = s.OAuthIdentities.ListByClaim(string(name), value)
		if err != nil {
			return nil, err
		}

		for _, i := range oauths {
			if i.UserID == info.UserID {
				continue
			}
			duplicate = i.ToInfo()
			err = identity.ErrIdentityAlreadyExists
			return
		}
	}

	// 2. Check duplicate by considering type-specific unique key.
	switch info.Type {
	case model.IdentityTypeLoginID:
		var i *identity.LoginID
		i, err = s.LoginIDIdentities.GetByUniqueKey(info.LoginID.UniqueKey)
		if err != nil {
			if !errors.Is(err, identity.ErrIdentityNotFound) {
				return
			}
			err = nil
		} else if i.UserID != info.UserID {
			duplicate = i.ToInfo()
			err = identity.ErrIdentityAlreadyExists
		}
	case model.IdentityTypeOAuth:
		var o *identity.OAuth
		o, err = s.OAuthIdentities.GetByProviderSubject(info.OAuth.ProviderID, info.OAuth.ProviderSubjectID)
		if err != nil {
			if !errors.Is(err, identity.ErrIdentityNotFound) {
				return
			}
			err = nil
		} else if o.UserID != info.UserID {
			duplicate = o.ToInfo()
			err = identity.ErrIdentityAlreadyExists
		}
	}

	return
}

func (s *Service) CreateIdentity(info *identity.Info) error {
	switch info.Type {
	case model.IdentityTypeLoginID:
		i := info.LoginID
		if err := s.LoginIDIdentities.Create(i); err != nil {
			return err
		}
		*info = *i.ToInfo()

	case model.IdentityTypeOAuth:
		i := info.OAuth
		if err := s.OAuthIdentities.Create(i); err != nil {
			return err
		}
		*info = *i.ToInfo()

	case model.IdentityTypeAnonymous:
		i := info.Anonymous
		if err := s.AnonymousIdentities.Create(i); err != nil {
			return err
		}
		*info = *i.ToInfo()

	case model.IdentityTypeBiometric:
		i := info.Biometric
		if err := s.BiometricIdentities.Create(i); err != nil {
			return err
		}
		*info = *i.ToInfo()
	case model.IdentityTypePasskey:
		i := info.Passkey
		if err := s.PasskeyIdentities.Create(i); err != nil {
			return err
		}
		*info = *i.ToInfo()
	case model.IdentityTypeSIWE:
		i := info.SIWE
		if err := s.SIWEIdentities.Create(i); err != nil {
			return err
		}
		*info = *i.ToInfo()
	default:
		panic("identity: unknown identity type " + info.Type)
	}
	return nil
}

func (s *Service) getIdentityBySpec(spec *identity.Spec) (*identity.Info, error) {
	switch spec.Type {
	case model.IdentityTypeLoginID:
		loginID := spec.LoginID.Value
		l, err := s.LoginIDIdentities.GetByValue(loginID)
		if err != nil {
			return nil, err
		} else if len(l) != 1 {
			return nil, identity.ErrIdentityNotFound
		}
		return l[0].ToInfo(), nil
	case model.IdentityTypeOAuth:
		o, err := s.OAuthIdentities.GetByProviderSubject(spec.OAuth.ProviderID, spec.OAuth.SubjectID)
		if err != nil {
			return nil, err
		}
		return o.ToInfo(), nil
	case model.IdentityTypeAnonymous:
		keyID := spec.Anonymous.KeyID
		if keyID != "" {
			a, err := s.AnonymousIdentities.GetByKeyID(keyID)
			if err != nil {
				return nil, err
			}
			return a.ToInfo(), nil
		}
		// when keyID is empty, try to get the identity from user and identity id
		userID := spec.Anonymous.ExistingUserID
		identityID := spec.Anonymous.ExistingIdentityID
		if userID == "" {
			return nil, identity.ErrIdentityNotFound
		}
		a, err := s.AnonymousIdentities.Get(userID, identityID)
		// identity must be found with existing user and identity id
		if err != nil {
			panic(fmt.Errorf("identity: failed to fetch anonymous identity: %s, %s, %w", userID, identityID, err))
		}
		return a.ToInfo(), nil
	case model.IdentityTypeBiometric:
		keyID := spec.Biometric.KeyID
		b, err := s.BiometricIdentities.GetByKeyID(keyID)
		if err != nil {
			return nil, err
		}
		return b.ToInfo(), nil
	case model.IdentityTypePasskey:
		assertionResponse := spec.Passkey.AssertionResponse
		p, err := s.PasskeyIdentities.GetByAssertionResponse(assertionResponse)
		if err != nil {
			return nil, err
		}
		return p.ToInfo(), nil
	case model.IdentityTypeSIWE:
		message := spec.SIWE.Message
		signature := spec.SIWE.Signature
		e, err := s.SIWEIdentities.GetByMessage(message, signature)
		if err != nil {
			return nil, err
		}
		return e.ToInfo(), nil
	}

	panic("identity: unknown identity type " + spec.Type)
}

func (s *Service) getIdentityRefByID(id string) (*model.IdentityRef, error) {
	builder := s.SQLBuilder.
		Select("id", "type", "user_id", "created_at", "updated_at").
		Where("id = ?", id).
		From(s.SQLBuilder.TableName("_auth_identity"))

	row, err := s.SQLExecutor.QueryRowWith(builder)
	if err != nil {
		return nil, err
	}

	ref, err := s.scanIdentityRef(row)
	if err != nil {
		return nil, err
	}

	return ref, nil
}

func (s *Service) scanIdentityRef(scanner db.Scanner) (*model.IdentityRef, error) {
	ref := &model.IdentityRef{}
	err := scanner.Scan(
		&ref.ID,
		&ref.Type,
		&ref.UserID,
		&ref.CreatedAt,
		&ref.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return ref, nil
}

func (s *Service) listIdentityRefsOfUser(userID string) ([]*model.IdentityRef, error) {
	builder := s.SQLBuilder.
		Select("id", "type", "user_id", "created_at", "updated_at").
		Where("user_id = ?", userID).
		From(s.SQLBuilder.TableName("_auth_identity"))

	rows, err := s.SQLExecutor.QueryWith(builder)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var refs []*model.IdentityRef
	for rows.Next() {
		var ref *model.IdentityRef
		ref, err = s.scanIdentityRef(rows)
		if err != nil {
			return nil, err
		}
		refs = append(refs, ref)
	}

	return refs, nil
}
