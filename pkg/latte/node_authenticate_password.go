package latte

import (
	"context"
	"errors"

	"github.com/authgear/authgear-server/pkg/api"
	"github.com/authgear/authgear-server/pkg/api/model"
	"github.com/authgear/authgear-server/pkg/lib/accounts"
	"github.com/authgear/authgear-server/pkg/lib/authn"
	"github.com/authgear/authgear-server/pkg/lib/authn/authenticator"
	"github.com/authgear/authgear-server/pkg/lib/workflow"
)

func init() {
	workflow.RegisterNode(&NodeAuthenticatePassword{})
}

type NodeAuthenticatePassword struct {
	UserID            string             `json:"user_id,omitempty"`
	AuthenticatorKind authenticator.Kind `json:"authenticator_kind,omitempty"`
}

func (n *NodeAuthenticatePassword) Kind() string {
	return "latte.NodeAuthenticatePassword"
}

func (n *NodeAuthenticatePassword) GetEffects(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) (effs []workflow.Effect, err error) {
	return nil, nil
}

func (n *NodeAuthenticatePassword) CanReactTo(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) ([]workflow.Input, error) {
	return []workflow.Input{
		&InputTakePassword{},
	}, nil
}

func (n *NodeAuthenticatePassword) ReactTo(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows, input workflow.Input) (*workflow.Node, error) {
	var inputTakePassword inputTakePassword
	switch {
	case workflow.AsInput(input, &inputTakePassword):
		info, err := n.getPasswordAuthenticator(deps)
		// The user doesn't have the password authenticator
		// always returns invalid credentials error
		if errors.Is(err, api.ErrNoAuthenticator) {
			return nil, api.ErrInvalidCredentials
		} else if err != nil {
			return nil, err
		}
		spec := &authenticator.Spec{
			Password: &authenticator.PasswordSpec{
				PlainPassword: inputTakePassword.GetPassword(),
			},
		}
		result, err := deps.Accounts.VerifyAuthenticatorsWithSpec(
			[]*authenticator.Info{info},
			spec,
			&accounts.VerifyAuthenticatorOptions{
				UserID:             info.UserID,
				Stage:              authn.AuthenticationStageSecondary,
				AuthenticatorType:  info.Type,
				AuthenticationType: authn.AuthenticationTypePassword,
			},
		)
		if err != nil {
			return nil, err
		}

		n, err := NewNodeVerifiedAuthenticator(ctx, deps, result)
		if err != nil {
			return nil, err
		}
		return workflow.NewNodeSimple(n), nil
	}
	return nil, workflow.ErrIncompatibleInput
}

func (n *NodeAuthenticatePassword) OutputData(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) (interface{}, error) {
	return map[string]interface{}{}, nil
}

func (n *NodeAuthenticatePassword) getPasswordAuthenticator(deps *workflow.Dependencies) (*authenticator.Info, error) {
	// FIXME(workflow): retrieve dependency elsewhere
	ais, err := deps.Accounts.ListAuthenticatorsOfUser(n.UserID)
	if err != nil {
		return nil, err
	}
	ais = authenticator.ApplyFilters(
		ais,
		authenticator.KeepKind(n.AuthenticatorKind),
		authenticator.KeepType(model.AuthenticatorTypePassword),
	)

	if len(ais) == 0 {
		return nil, api.ErrNoAuthenticator
	}

	return ais[0], nil
}
