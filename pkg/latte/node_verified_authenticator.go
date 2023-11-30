package latte

import (
	"context"

	"github.com/authgear/authgear-server/pkg/api/model"
	"github.com/authgear/authgear-server/pkg/lib/accounts"
	"github.com/authgear/authgear-server/pkg/lib/config"
	"github.com/authgear/authgear-server/pkg/lib/feature/verification"
	"github.com/authgear/authgear-server/pkg/lib/workflow"
)

func init() {
	workflow.RegisterNode(&NodeVerifiedAuthenticator{})
}

type NodeVerifiedAuthenticator struct {
	Result           *accounts.VerifyAuthenticatorResult `json:"result,omitempty"`
	NewVerifiedClaim *verification.Claim                 `json:"new_verified_claim,omitempty"`
}

func NewNodeVerifiedAuthenticator(ctx context.Context, deps *workflow.Dependencies, result *accounts.VerifyAuthenticatorResult) (*NodeVerifiedAuthenticator, error) {
	userID := result.UsedAuthenticator.UserID

	// Mark authenticator as verified after login
	var verifiedClaim *verification.Claim

	// FIXME(workflow): retrieve dependency elsewhere
	claims, err := deps.Accounts.ListVerifiedClaimsOfUser(userID)
	if err != nil {
		return nil, err
	}

	switch result.UsedAuthenticator.Type {
	case model.AuthenticatorTypeOOBEmail:
		verifiedClaim, _ = deps.Accounts.NewVerifiedClaim(claims, userID, string(model.ClaimEmail), result.UsedAuthenticator.OOBOTP.Email)
	case model.AuthenticatorTypeOOBSMS:
		verifiedClaim, _ = deps.Accounts.NewVerifiedClaim(claims, userID, string(model.ClaimPhoneNumber), result.UsedAuthenticator.OOBOTP.Phone)
	}

	return &NodeVerifiedAuthenticator{
		Result:           result,
		NewVerifiedClaim: verifiedClaim,
	}, nil
}

func (n *NodeVerifiedAuthenticator) Kind() string {
	// FIXME: It should be NodeVerifiedAuthenticator
	return "latte.NodeAuthenticateOOBOTPPhoneEnd"
}

func (n *NodeVerifiedAuthenticator) GetEffects(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) (effs []workflow.Effect, err error) {
	return []workflow.Effect{
		workflow.RunEffect(func(ctx context.Context, deps *workflow.Dependencies) error {
			if n.NewVerifiedClaim != nil {
				return deps.AccountWriter.CreateVerifiedClaim(n.NewVerifiedClaim)
			}
			return nil
		}),
	}, nil
}

func (*NodeVerifiedAuthenticator) CanReactTo(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) ([]workflow.Input, error) {
	return nil, workflow.ErrEOF
}

func (*NodeVerifiedAuthenticator) ReactTo(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows, input workflow.Input) (*workflow.Node, error) {
	return nil, workflow.ErrIncompatibleInput
}

func (n *NodeVerifiedAuthenticator) OutputData(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) (interface{}, error) {
	return map[string]interface{}{}, nil
}

func (n *NodeVerifiedAuthenticator) GetAMR() []string {
	return n.Result.UsedAuthenticator.AMR()
}

var _ VerifiedAuthenticationLockoutMethodGetter = &NodeVerifiedAuthenticator{}

func (n *NodeVerifiedAuthenticator) GetVerifiedAuthenticationLockoutMethod() (config.AuthenticationLockoutMethod, bool) {
	if n.Result.UsedAuthenticator != nil {
		return config.AuthenticationLockoutMethodFromAuthenticatorType(n.Result.UsedAuthenticator.Type)
	}
	return "", false
}
