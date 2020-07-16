package interaction

import (
	"errors"
	"fmt"

	"github.com/authgear/authgear-server/pkg/auth/dependency/authenticator"
	"github.com/authgear/authgear-server/pkg/auth/dependency/identity"
	"github.com/authgear/authgear-server/pkg/auth/event"
	"github.com/authgear/authgear-server/pkg/core/authn"
)

func (p *Provider) Commit(i *Interaction) (*Result, error) {
	var err error
	switch intent := i.Intent.(type) {
	case *IntentLogin:
		err = p.onCommitLogin(i, intent)
	case *IntentSignup:
		err = p.onCommitSignup(i, intent)
	case *IntentAddIdentity:
		err = p.onCommitAddIdentity(i, intent)
	case *IntentRemoveIdentity:
		err = p.onCommitRemoveIdentity(i, intent)
	case *IntentUpdateIdentity:
		err = p.onCommitUpdateIdentity(i, intent)
	case *IntentUpdateAuthenticator:
		break
	default:
		panic(fmt.Sprintf("interaction: unknown intent type %T", i.Intent))
	}
	if err != nil {
		return nil, err
	}

	// Create identities & authenticators
	if err := p.Identity.CreateAll(i.NewIdentities); err != nil {
		return nil, err
	}
	if err := p.Authenticator.CreateAll(i.UserID, i.NewAuthenticators); err != nil {
		return nil, err
	}

	// Update identities
	if err := p.Identity.UpdateAll(i.UpdateIdentities); err != nil {
		return nil, err
	}

	// Update authenticators
	if err := p.Authenticator.UpdateAll(i.UserID, i.UpdateAuthenticators); err != nil {
		return nil, err
	}

	var identity *identity.Info
	if i.Identity != nil {
		ii, err := p.Identity.Get(i.UserID, i.Identity.Type, i.Identity.ID)
		if err != nil {
			return nil, err
		}
		identity = ii
	}

	var primaryAuthenticator *authenticator.Info
	if i.PrimaryAuthenticator != nil {
		aa, err := p.Authenticator.Get(i.UserID, i.PrimaryAuthenticator.Type, i.PrimaryAuthenticator.ID)
		if err != nil {
			return nil, err
		}
		primaryAuthenticator = aa
	}

	var secondaryAuthenticator *authenticator.Info
	if i.SecondaryAuthenticator != nil {
		aa, err := p.Authenticator.Get(i.UserID, i.SecondaryAuthenticator.Type, i.SecondaryAuthenticator.ID)
		if err != nil {
			return nil, err
		}
		secondaryAuthenticator = aa
	}

	// Delete identities & authenticators
	if err := p.Identity.DeleteAll(i.RemoveIdentities); err != nil {
		return nil, err
	}
	if err := p.Authenticator.DeleteAll(i.UserID, i.RemoveAuthenticators); err != nil {
		return nil, err
	}

	attrs := &authn.Attrs{
		UserID: i.UserID,
		// TODO(interaction): populate ACR
		AMR: DeriveAMR(primaryAuthenticator, secondaryAuthenticator),
	}

	return &Result{
		Attrs:                  attrs,
		Identity:               identity,
		PrimaryAuthenticator:   primaryAuthenticator,
		SecondaryAuthenticator: secondaryAuthenticator,
	}, nil
}

func (p *Provider) onCommitLogin(i *Interaction, intent *IntentLogin) error {
	if intent.Identity.Type == authn.IdentityTypeOAuth {
		// skip update if login is triggered by signup
		if intent.OriginalIntentType == IntentTypeSignup {
			return nil
		}

		ii, err := p.Identity.Get(i.UserID, intent.Identity.Type, i.Identity.ID)
		if err != nil {
			p.Logger.WithError(err).Warn("failed to new identity for update")
			return err
		}
		ui, err := p.Identity.WithClaims(ii, intent.Identity.Claims)
		if err != nil {
			return err
		}
		i.UpdateIdentities = append(i.UpdateIdentities, ui)
	}

	return nil
}

func (p *Provider) onCommitSignup(i *Interaction, intent *IntentSignup) error {
	err := p.checkIdentitiesDuplicated(i.NewIdentities)
	if err != nil {
		return err
	}

	err = p.User.Create(i.UserID, intent.UserMetadata, i.NewIdentities, i.NewAuthenticators)
	if err != nil {
		return err
	}

	return nil
}

func (p *Provider) onCommitAddIdentity(i *Interaction, intent *IntentAddIdentity) error {
	err := p.checkIdentitiesDuplicated(i.NewIdentities)
	if err != nil {
		return err
	}

	user, err := p.User.Get(i.UserID)
	if err != nil {
		return err
	}

	for _, i := range i.NewIdentities {
		identity := i.ToModel()
		err = p.Hooks.DispatchEvent(
			event.IdentityCreateEvent{
				User:     *user,
				Identity: identity,
			},
			user,
		)
		if err != nil {
			return err
		}
	}

	return nil
}

func (p *Provider) onCommitRemoveIdentity(i *Interaction, intent *IntentRemoveIdentity) error {
	// populate remove authenticators
	ois, err := p.Identity.ListByUser(i.UserID)
	if err != nil {
		return err
	}

	removeIdentitiesID := map[string]interface{}{}
	keepAuthenticators := map[string]*authenticator.Info{}
	allAuthenticators := map[string]*authenticator.Info{}

	// compute set of removing identities id
	for _, iden := range i.RemoveIdentities {
		removeIdentitiesID[iden.ID] = struct{}{}
	}

	for _, oi := range ois {
		authenticators, err := p.Authenticator.ListByIdentity(i.UserID, oi)
		if err != nil {
			return err
		}
		_, toRemove := removeIdentitiesID[oi.ID]
		for _, a := range authenticators {
			allAuthenticators[a.ID] = a
			if !toRemove {
				keepAuthenticators[a.ID] = a
			}
		}
	}

	for _, a := range allAuthenticators {
		if _, ok := keepAuthenticators[a.ID]; !ok {
			// not found in the keep authenticators list
			i.RemoveAuthenticators = append(i.RemoveAuthenticators, a)
		}
	}

	// remove identity event
	user, err := p.User.Get(i.UserID)
	if err != nil {
		return err
	}

	for _, i := range i.RemoveIdentities {
		identity := i.ToModel()
		err = p.Hooks.DispatchEvent(
			event.IdentityDeleteEvent{
				User:     *user,
				Identity: identity,
			},
			user,
		)
		if err != nil {
			return err
		}
	}

	return nil
}

func (p *Provider) onCommitUpdateIdentity(i *Interaction, intent *IntentUpdateIdentity) error {
	err := p.checkIdentitiesDuplicated(i.UpdateIdentities)
	if err != nil {
		return err
	}

	if len(i.UpdateIdentities) != 1 {
		panic("interaction: unexpected number of identities to be updated")
	}

	var originalIdentityInfo *identity.Info
	updateIdentityInfo := i.UpdateIdentities[0]

	// check if there is any authenticators need to be deleted after identity update
	keepAuthenticators := map[string]*authenticator.Info{}
	allAuthenticators := map[string]*authenticator.Info{}

	ois, err := p.Identity.ListByUser(i.UserID)
	if err != nil {
		return err
	}

	for _, oi := range ois {
		authenticators, err := p.Authenticator.ListByIdentity(i.UserID, oi)
		if err != nil {
			return err
		}
		toRemove := updateIdentityInfo.ID == oi.ID
		for _, a := range authenticators {
			allAuthenticators[a.ID] = a
			if toRemove {
				// authenticators get by the original identity info
				originalIdentityInfo = oi
			} else {
				// authenticators of the existing identities
				keepAuthenticators[a.ID] = a
			}
		}
	}

	if originalIdentityInfo == nil {
		panic("interaction: unexpected original identity info not found")
	}

	// authenticators get by the updated identity info
	authenticators, err := p.Authenticator.ListByIdentity(i.UserID, updateIdentityInfo)
	if err != nil {
		return err
	}
	for _, a := range authenticators {
		keepAuthenticators[a.ID] = a
	}

	for _, a := range allAuthenticators {
		if _, ok := keepAuthenticators[a.ID]; !ok {
			// not found in the keep authenticators list
			i.RemoveAuthenticators = append(i.RemoveAuthenticators, a)
		}
	}

	// update identity event
	user, err := p.User.Get(i.UserID)
	if err != nil {
		return err
	}
	originalIdentity := originalIdentityInfo.ToModel()
	updatedIdentity := updateIdentityInfo.ToModel()
	err = p.Hooks.DispatchEvent(
		event.IdentityUpdateEvent{
			User:        *user,
			OldIdentity: originalIdentity,
			NewIdentity: updatedIdentity,
		},
		user,
	)
	if err != nil {
		return err
	}
	return nil
}

func (p *Provider) checkIdentitiesDuplicated(iis []*identity.Info) error {
	for _, i := range iis {
		err := p.Identity.CheckIdentityDuplicated(i)
		if err != nil {
			if errors.Is(err, identity.ErrIdentityAlreadyExists) {
				err = ErrDuplicatedIdentity
			}
			return err
		}
	}
	return nil
}
