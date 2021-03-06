package flows

import (
	"github.com/skygeario/skygear-server/pkg/auth/dependency/identity"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/identity/oauth"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/interaction"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/sso"
	"github.com/skygeario/skygear-server/pkg/auth/event"
	"github.com/skygeario/skygear-server/pkg/auth/model"
	"github.com/skygeario/skygear-server/pkg/core/authn"
	"github.com/skygeario/skygear-server/pkg/core/config"
	"github.com/skygeario/skygear-server/pkg/core/errors"
)

const (
	// WebAppExtraStatePromotion is a extra state indicating the interaction
	// is for anonymous user promotion. It contains the anonymous user ID
	WebAppExtraStateAnonymousUserPromotion string = "https://auth.skygear.io/claims/web_app/anonymous_user_promotion"
)

func (f *WebAppFlow) PromoteWithLoginID(loginIDKey, loginID string, userID string) (*WebAppResult, error) {
	var err error

	var i *interaction.Interaction
	iden := identity.Spec{
		Type: authn.IdentityTypeLoginID,
		Claims: map[string]interface{}{
			identity.IdentityClaimLoginIDKey:   loginIDKey,
			identity.IdentityClaimLoginIDValue: loginID,
		},
	}

	if f.ConflictConfig.Promotion == config.PromotionConflictBehaviorLogin {
		_, _, err = f.Identities.GetByClaims(authn.IdentityTypeLoginID, iden.Claims)
		if errors.Is(err, identity.ErrIdentityNotFound) {
			i, err = f.Interactions.NewInteractionAddIdentity(&interaction.IntentAddIdentity{
				Identity: iden,
			}, "", userID)
		} else if err != nil {
			return nil, err
		} else {
			i, err = f.Interactions.NewInteractionLogin(&interaction.IntentLogin{
				Identity: iden,
			}, "")
		}
	} else {
		i, err = f.Interactions.NewInteractionAddIdentity(&interaction.IntentAddIdentity{
			Identity: iden,
		}, "", userID)
	}
	if err != nil {
		return nil, err
	}

	var step WebAppStep
	if i.Intent.Type() == interaction.IntentTypeLogin {
		step, err = f.handleLogin(i)
	} else {
		step, err = f.handleSignup(i)
	}
	if err != nil {
		return nil, err
	}

	i.Extra[WebAppExtraStateAnonymousUserPromotion] = userID

	token, err := f.Interactions.SaveInteraction(i)
	if err != nil {
		return nil, err
	}

	return &WebAppResult{
		Step:  step,
		Token: token,
	}, nil
}

func (f *WebAppFlow) PromoteWithOAuthProvider(userID string, oauthAuthInfo sso.AuthInfo) (*WebAppResult, error) {
	providerID := oauth.NewProviderID(oauthAuthInfo.ProviderConfig)
	iden := identity.Spec{
		Type: authn.IdentityTypeOAuth,
		Claims: map[string]interface{}{
			identity.IdentityClaimOAuthProviderKeys: providerID.ClaimsValue(),
			identity.IdentityClaimOAuthSubjectID:    oauthAuthInfo.ProviderUserInfo.ID,
			identity.IdentityClaimOAuthProfile:      oauthAuthInfo.ProviderRawProfile,
			identity.IdentityClaimOAuthClaims:       oauthAuthInfo.ProviderUserInfo.ClaimsValue(),
		},
	}
	var err error

	var i *interaction.Interaction
	if f.ConflictConfig.Promotion == config.PromotionConflictBehaviorLogin {
		_, _, err = f.Identities.GetByClaims(authn.IdentityTypeOAuth, iden.Claims)
		if errors.Is(err, identity.ErrIdentityNotFound) {
			i, err = f.Interactions.NewInteractionAddIdentity(&interaction.IntentAddIdentity{
				Identity: iden,
			}, "", userID)
		} else if err != nil {
			return nil, err
		} else {
			i, err = f.Interactions.NewInteractionLogin(&interaction.IntentLogin{
				Identity: iden,
			}, "")
		}
	} else {
		i, err = f.Interactions.NewInteractionAddIdentity(&interaction.IntentAddIdentity{
			Identity: iden,
		}, "", userID)
	}
	if err != nil {
		return nil, err
	}

	s, err := f.Interactions.GetInteractionState(i)
	if err != nil {
		return nil, err
	} else if s.CurrentStep().Step != interaction.StepCommit {
		// authenticator is not needed for oauth identity
		// so the current step must be commit
		panic("interaction_flow_webapp: unexpected interaction step")
	}

	i.Extra[WebAppExtraStateAnonymousUserPromotion] = userID

	result, err := f.Interactions.Commit(i)
	if err != nil {
		return nil, err
	}

	return f.afterAnonymousUserPromotion(i, result)
}

func (f *WebAppFlow) afterAnonymousUserPromotion(i *interaction.Interaction, ir *interaction.Result) (*WebAppResult, error) {
	var err error
	anonUserID := i.Extra[WebAppExtraStateAnonymousUserPromotion]

	anonUser, err := f.Users.Get(anonUserID)
	if err != nil {
		return nil, err
	}

	// Remove anonymous identity if the same user is reused
	if anonUserID == ir.Attrs.UserID {
		i, err = f.Interactions.NewInteractionRemoveIdentity(&interaction.IntentRemoveIdentity{
			Identity: identity.Spec{
				Type:   authn.IdentityTypeAnonymous,
				Claims: map[string]interface{}{},
			},
		}, "", anonUserID)
		if err != nil {
			return nil, err
		}

		s, err := f.Interactions.GetInteractionState(i)
		if err != nil {
			return nil, err
		}

		if s.CurrentStep().Step != interaction.StepCommit {
			panic("interaction_flow_webapp: unexpected step " + s.CurrentStep().Step)
		}

		_, err = f.Interactions.Commit(i)
		if err != nil {
			return nil, err
		}
	}

	user, err := f.Users.Get(ir.Attrs.UserID)
	if err != nil {
		return nil, err
	}

	err = f.Hooks.DispatchEvent(
		event.UserPromoteEvent{
			AnonymousUser: *anonUser,
			User:          *user,
			Identities: []model.Identity{
				ir.Identity.ToModel(),
			},
		},
		user,
	)
	if err != nil {
		return nil, err
	}

	result, err := f.UserController.CreateSession(i, ir)
	if err != nil {
		return nil, err
	}

	// NOTE: existing anonymous sessions are not deleted, in case of commit
	// failure may cause lost users.

	return &WebAppResult{
		Step:    WebAppStepCompleted,
		Cookies: result.Cookies,
	}, nil
}
