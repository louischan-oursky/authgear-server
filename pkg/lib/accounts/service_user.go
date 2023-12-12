package accounts

import (
	"time"

	"github.com/authgear/authgear-server/pkg/lib/authn/attrs"
	"github.com/authgear/authgear-server/pkg/lib/authn/identity"
	"github.com/authgear/authgear-server/pkg/lib/authn/stdattrs"
	"github.com/authgear/authgear-server/pkg/lib/authn/user"
	"github.com/authgear/authgear-server/pkg/util/accesscontrol"
)

func (s *Service) GetUserByID(id string) (*user.User, error) {
	return s.Users.Get(id)
}

func (s *Service) NewUser(id string) *user.User {
	now := s.Clock.NowUTC()
	user := &user.User{
		ID:                 id,
		CreatedAt:          now,
		UpdatedAt:          now,
		MostRecentLoginAt:  nil,
		LessRecentLoginAt:  nil,
		IsDisabled:         false,
		DisableReason:      nil,
		StandardAttributes: make(map[string]interface{}),
		CustomAttributes:   make(map[string]interface{}),
	}
	return user
}

func (s *Service) UpdateUserLoginTime(u *user.User, loginAt time.Time) *user.User {
	uu := *u
	uu.LessRecentLoginAt = uu.MostRecentLoginAt
	uu.MostRecentLoginAt = &loginAt
	return &uu
}

func (s *Service) PopulateStandardAttribute(u *user.User, info *identity.Info) *user.User {
	stdAttrsFromIden := stdattrs.T(info.AllStandardClaims()).NonIdentityAware()
	originalStdAttrs := stdattrs.T(u.StandardAttributes)
	stdAttrs := originalStdAttrs.MergedWith(stdAttrsFromIden)

	uu := *u
	uu.StandardAttributes = stdAttrs.ToClaims()
	uu.UpdatedAt = s.Clock.NowUTC()
	return &uu
}

func (s *Service) UpdateStandardAttributesWithList(role accesscontrol.Role, u *user.User, identities []*identity.Info, attrs attrs.List) (*user.User, error) {
	originalStdAttrs := stdattrs.T(u.StandardAttributes)
	stdAttrs, err := originalStdAttrs.MergedWithList(attrs)
	if err != nil {
		return nil, err
	}

	stdAttrs, err = s.StandardAttributes.UpdateStandardAttributes0(role, u, identities, stdAttrs)
	if err != nil {
		return nil, err
	}

	uu := *u
	uu.StandardAttributes = stdAttrs
	uu.UpdatedAt = s.Clock.NowUTC()
	return &uu, nil
}

func (s *Service) ReplaceStandardAttributes(role accesscontrol.Role, u *user.User, identities []*identity.Info, stdAttrs map[string]interface{}) (*user.User, error) {
	stdAttrs, err := s.StandardAttributes.UpdateStandardAttributes0(role, u, identities, stdAttrs)
	if err != nil {
		return nil, err
	}

	uu := *u
	uu.StandardAttributes = stdAttrs
	uu.UpdatedAt = s.Clock.NowUTC()
	return &uu, nil
}

func (s *Service) ReplaceCustomAttributes(role accesscontrol.Role, u *user.User, reprForm map[string]interface{}) (*user.User, error) {
	storageForm, err := s.CustomAttributes.UpdateAllCustomAttributes0(role, u, reprForm)
	if err != nil {
		return nil, err
	}

	uu := *u
	uu.CustomAttributes = storageForm
	uu.UpdatedAt = s.Clock.NowUTC()
	return &uu, nil
}
