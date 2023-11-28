package accounts

import (
	"time"

	"github.com/authgear/authgear-server/pkg/lib/authn/user"
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

func (s *Service) CreateUser(u *user.User) error {
	return s.Users.Create(u)
}

func (s *Service) UpdateUserLoginTime(u *user.User, loginAt time.Time) *user.User {
	uu := *u
	uu.LessRecentLoginAt = uu.MostRecentLoginAt
	uu.MostRecentLoginAt = &loginAt
	return &uu
}
