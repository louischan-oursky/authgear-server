package accounts

import (
	"errors"
	"fmt"

	"github.com/authgear/authgear-server/pkg/api/model"
	"github.com/authgear/authgear-server/pkg/lib/authn/authenticator"
	"github.com/authgear/authgear-server/pkg/lib/authn/identity"
	"github.com/authgear/authgear-server/pkg/lib/authn/identity/loginid"
	"github.com/authgear/authgear-server/pkg/lib/authn/user"
	"github.com/authgear/authgear-server/pkg/lib/config"
	"github.com/authgear/authgear-server/pkg/lib/feature/verification"
	"github.com/authgear/authgear-server/pkg/lib/infra/db"
)

type NewIdentityChanges struct {
	UpdatedUser       *user.User
	NewIdentity       *identity.Info
	NewVerifiedClaims []*verification.Claim
}

type UpdateIdentityChanges struct {
	UpdatedUser           *user.User
	UpdatedIdentity       *identity.Info
	NewVerifiedClaims     []*verification.Claim
	UpdatedAuthenticators []*authenticator.Info
	RemovedVerifiedClaims []*verification.Claim
}

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

func (s *Service) GetNewIdentityChanges(spec *identity.Spec, u *user.User, identities []*identity.Info, claims []*verification.Claim) (*NewIdentityChanges, error) {
	switch spec.Type {
	case model.IdentityTypeLoginID:
		l, err := s.LoginIDIdentities.New(u.ID, *spec.LoginID, loginid.CheckerOptions{
			// The use case of NewIdentity does not bypass.
			EmailByPassBlocklistAllowlist: false,
		})
		if err != nil {
			return nil, err
		}
		return s.getNewIdentityChanges(l.ToInfo(), u, identities, claims)
	case model.IdentityTypeOAuth:
		providerID := spec.OAuth.ProviderID
		subjectID := spec.OAuth.SubjectID
		rawProfile := spec.OAuth.RawProfile
		standardClaims := spec.OAuth.StandardClaims
		o := s.OAuthIdentities.New(u.ID, providerID, subjectID, rawProfile, standardClaims)
		return s.getNewIdentityChanges(o.ToInfo(), u, identities, claims)
	case model.IdentityTypeAnonymous:
		keyID := spec.Anonymous.KeyID
		key := spec.Anonymous.Key
		a := s.AnonymousIdentities.New(u.ID, keyID, []byte(key))
		return s.getNewIdentityChanges(a.ToInfo(), u, identities, claims)
	case model.IdentityTypeBiometric:
		keyID := spec.Biometric.KeyID
		key := spec.Biometric.Key
		deviceInfo := spec.Biometric.DeviceInfo
		b := s.BiometricIdentities.New(u.ID, keyID, []byte(key), deviceInfo)
		return s.getNewIdentityChanges(b.ToInfo(), u, identities, claims)
	case model.IdentityTypePasskey:
		attestationResponse := spec.Passkey.AttestationResponse
		p, err := s.PasskeyIdentities.New(u.ID, attestationResponse)
		if err != nil {
			return nil, err
		}
		return s.getNewIdentityChanges(p.ToInfo(), u, identities, claims)
	case model.IdentityTypeSIWE:
		message := spec.SIWE.Message
		signature := spec.SIWE.Signature
		e, err := s.SIWEIdentities.New(u.ID, message, signature)
		if err != nil {
			return nil, err
		}
		return s.getNewIdentityChanges(e.ToInfo(), u, identities, claims)
	}

	panic("identity: unknown identity type " + spec.Type)
}

func (s *Service) getNewIdentityChanges(
	info *identity.Info,
	u *user.User,
	identities []*identity.Info,
	claims []*verification.Claim,
) (*NewIdentityChanges, error) {
	changes := &NewIdentityChanges{}
	changes.NewIdentity = info
	identities = s.identitiesSlice(identities, []*identity.Info{info})

	claim, ok := s.markOAuthEmailAsVerified(info, claims)
	if ok {
		changes.NewVerifiedClaims = append(changes.NewVerifiedClaims, claim)
		claims = s.claimsSlice(claims, []*verification.Claim{claim})
	}

	stdAttrs, ok := s.StandardAttributes.PopulateIdentityAwareStandardAttributes0(u.StandardAttributes, identities)
	if ok {
		uu := *u
		uu.StandardAttributes = stdAttrs
		uu.UpdatedAt = s.Clock.NowUTC()
		changes.UpdatedUser = &uu
	}

	return changes, nil
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

func (s *Service) GetUpdateIdentityChanges(
	info *identity.Info,
	spec *identity.Spec,
	u *user.User,
	identities []*identity.Info,
	authenticators []*authenticator.Info,
	claims []*verification.Claim,
) (*UpdateIdentityChanges, error) {
	switch info.Type {
	case model.IdentityTypeLoginID:
		i, err := s.LoginIDIdentities.WithValue(info.LoginID, spec.LoginID.Value, loginid.CheckerOptions{
			// The use case of GetUpdateIdentityChanges does not bypass.
			EmailByPassBlocklistAllowlist: false,
		})
		if err != nil {
			return nil, err
		}

		updated := i.ToInfo()
		return s.getUpdateIdentityChanges(info, updated, u, identities, authenticators, claims)
	case model.IdentityTypeOAuth:
		rawProfile := spec.OAuth.RawProfile
		standardClaims := spec.OAuth.StandardClaims
		i := s.OAuthIdentities.WithUpdate(
			info.OAuth,
			rawProfile,
			standardClaims,
		)
		updated := i.ToInfo()
		return s.getUpdateIdentityChanges(info, updated, u, identities, authenticators, claims)
	default:
		panic("identity: cannot update identity type " + info.Type)
	}
}

func (s *Service) getUpdateIdentityChanges(
	oldInfo *identity.Info,
	newInfo *identity.Info,
	u *user.User,
	identities []*identity.Info,
	authenticators []*authenticator.Info,
	claims []*verification.Claim,
) (*UpdateIdentityChanges, error) {
	changes := &UpdateIdentityChanges{}
	changes.UpdatedIdentity = newInfo
	identities = s.identitiesSlice(identities, []*identity.Info{newInfo})

	claim, ok := s.markOAuthEmailAsVerified(newInfo, claims)
	if ok {
		changes.NewVerifiedClaims = append(changes.NewVerifiedClaims, claim)
		claims = s.claimsSlice(claims, []*verification.Claim{claim})
	}

	updatedAuthenticators, err := s.updateDependentAuthenticators(oldInfo, newInfo, authenticators)
	if err != nil {
		return nil, err
	}
	if len(updatedAuthenticators) > 0 {
		changes.UpdatedAuthenticators = append(changes.UpdatedAuthenticators, updatedAuthenticators...)
		authenticators = s.authenticatorsSlice(authenticators, updatedAuthenticators)
	}

	removedClaims := s.removeOrphanedClaims(identities, authenticators, claims)
	if len(removedClaims) > 0 {
		changes.RemovedVerifiedClaims = append(changes.RemovedVerifiedClaims, removedClaims...)
	}

	stdAttrs, ok := s.StandardAttributes.PopulateIdentityAwareStandardAttributes0(u.StandardAttributes, identities)
	if ok {
		uu := *u
		uu.StandardAttributes = stdAttrs
		uu.UpdatedAt = s.Clock.NowUTC()
		changes.UpdatedUser = &uu
	}

	return changes, nil
}

func (s *Service) removeOrphanedClaims(identities []*identity.Info, authenticators []*authenticator.Info, claims []*verification.Claim) []*verification.Claim {
	type claim struct {
		Name  string
		Value string
	}

	orphans := make(map[claim]*verification.Claim)
	for _, c := range claims {
		orphans[claim{c.Name, c.Value}] = c
	}

	for _, i := range identities {
		for name, value := range i.IdentityAwareStandardClaims() {
			delete(orphans, claim{Name: string(name), Value: value})
		}
	}

	for _, a := range authenticators {
		for name, value := range a.StandardClaims() {
			delete(orphans, claim{Name: string(name), Value: value})
		}
	}

	var out []*verification.Claim
	for _, claim := range orphans {
		out = append(out, claim)
	}

	return out
}

func (s *Service) updateDependentAuthenticators(oldInfo *identity.Info, newInfo *identity.Info, authenticators []*authenticator.Info) ([]*authenticator.Info, error) {
	var updated []*authenticator.Info

	for _, a := range authenticators {
		if a.IsDependentOf(oldInfo) {
			spec := &authenticator.Spec{
				Type:      a.Type,
				UserID:    a.UserID,
				IsDefault: a.IsDefault,
				Kind:      a.Kind,
			}
			switch a.Type {
			case model.AuthenticatorTypeOOBEmail:
				spec.OOBOTP = &authenticator.OOBOTPSpec{
					Email: newInfo.LoginID.LoginID,
				}
			case model.AuthenticatorTypeOOBSMS:
				spec.OOBOTP = &authenticator.OOBOTPSpec{
					Phone: newInfo.LoginID.LoginID,
				}
			}

			changed, newAuthenticator, err := s.UpdateAuthenticatorWithSpec(a, spec)
			if err != nil {
				return nil, err
			}
			if changed {
				updated = append(updated, newAuthenticator)
			}
		}
	}

	return updated, nil
}

func (s *Service) markOAuthEmailAsVerified(info *identity.Info, claims []*verification.Claim) (*verification.Claim, bool) {
	if info.Type != model.IdentityTypeOAuth {
		return nil, false
	}

	providerID := info.OAuth.ProviderID

	var cfg *config.OAuthSSOProviderConfig
	for _, c := range s.IdentityConfig.OAuth.Providers {
		if c.ProviderID().Equal(&providerID) {
			c := c
			cfg = &c
			break
		}
	}

	standardClaims := info.IdentityAwareStandardClaims()

	email, ok := standardClaims[model.ClaimEmail]
	if ok && cfg != nil && *cfg.Claims.Email.AssumeVerified {
		// Mark as verified if OAuth email is assumed to be verified
		claim, ok := s.markVerified(info.UserID, claims, model.ClaimEmail, email)
		if ok {
			return claim, true
		}
	}

	return nil, false
}

func (s *Service) markVerified(userID string, existingClaims []*verification.Claim, claimName model.ClaimName, claimValue string) (*verification.Claim, bool) {
	for _, claim := range existingClaims {
		if claim.Name == string(claimName) && claim.Value == claimValue {
			return nil, false
		}
	}

	claim := s.NewVerifiedClaim(userID, string(claimName), claimValue)
	return claim, true
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
