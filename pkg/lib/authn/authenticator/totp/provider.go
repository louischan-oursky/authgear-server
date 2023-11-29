package totp

import (
	"fmt"
	"sort"

	"github.com/authgear/authgear-server/pkg/lib/authn/authenticator"
	"github.com/authgear/authgear-server/pkg/lib/config"
	"github.com/authgear/authgear-server/pkg/util/clock"
	"github.com/authgear/authgear-server/pkg/util/secretcode"
	"github.com/authgear/authgear-server/pkg/util/uuid"
)

type Provider struct {
	Store  *Store
	Config *config.AuthenticatorTOTPConfig
	Clock  clock.Clock
}

func (p *Provider) Get(userID string, id string) (*authenticator.TOTP, error) {
	return p.Store.Get(userID, id)
}

func (p *Provider) GetMany(ids []string) ([]*authenticator.TOTP, error) {
	return p.Store.GetMany(ids)
}

func (p *Provider) Delete(a *authenticator.TOTP) error {
	return p.Store.Delete(a.ID)
}

func (p *Provider) List(userID string) ([]*authenticator.TOTP, error) {
	authenticators, err := p.Store.List(userID)
	if err != nil {
		return nil, err
	}

	sortAuthenticators(authenticators)
	return authenticators, nil
}

func (p *Provider) New(id string, userID string, displayName string, isDefault bool, kind string) *authenticator.TOTP {
	totp, err := secretcode.NewTOTPFromRNG()
	if err != nil {
		panic(fmt.Errorf("totp: failed to generate secret: %w", err))
	}

	if id == "" {
		id = uuid.New()
	}
	now := p.Clock.NowUTC()
	a := &authenticator.TOTP{
		ID:          id,
		CreatedAt:   now,
		UpdatedAt:   now,
		UserID:      userID,
		Secret:      totp.Secret,
		DisplayName: displayName,
		IsDefault:   isDefault,
		Kind:        kind,
	}
	return a
}

func (p *Provider) Create(a *authenticator.TOTP) error {
	now := p.Clock.NowUTC()
	a.CreatedAt = now
	a.UpdatedAt = now
	return p.Store.Create(a)
}

func (p *Provider) Authenticate(a *authenticator.TOTP, code string) error {
	now := p.Clock.NowUTC()
	totp := secretcode.NewTOTPFromSecret(a.Secret)
	if totp.ValidateCode(now, code) {
		return nil
	}

	return ErrInvalidCode
}

func sortAuthenticators(as []*authenticator.TOTP) {
	sort.Slice(as, func(i, j int) bool {
		return as[i].CreatedAt.Before(as[j].CreatedAt)
	})
}
