package latte

import (
	"context"
	"errors"

	"github.com/authgear/authgear-server/pkg/api"
	"github.com/authgear/authgear-server/pkg/api/model"
	"github.com/authgear/authgear-server/pkg/lib/accounts"
	"github.com/authgear/authgear-server/pkg/lib/authn/authenticator"
	"github.com/authgear/authgear-server/pkg/lib/workflow"
)

func init() {
	workflow.RegisterNode(&NodeChangePassword{})
}

type NodeChangePassword struct {
	UserID            string             `json:"user_id,omitempty"`
	AuthenticatorKind authenticator.Kind `json:"authenticator_kind,omitempty"`
}

func (n *NodeChangePassword) Kind() string {
	return "latte.NodeChangePassword"
}

func (n *NodeChangePassword) GetEffects(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) (effs []workflow.Effect, err error) {
	return nil, nil
}

func (n *NodeChangePassword) CanReactTo(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) ([]workflow.Input, error) {
	return []workflow.Input{
		&InputChangePassword{},
	}, nil
}

func (n *NodeChangePassword) ReactTo(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows, input workflow.Input) (*workflow.Node, error) {
	var inputChangePassword inputChangePassword
	switch {
	case workflow.AsInput(input, &inputChangePassword):
		info, err := n.getPasswordAuthenticator(deps)
		// The user doesn't have the password authenticator
		// always returns no password error
		if errors.Is(err, api.ErrNoAuthenticator) {
			return nil, api.ErrNoPassword
		} else if err != nil {
			return nil, err
		}
		spec := &authenticator.Spec{
			Password: &authenticator.PasswordSpec{
				PlainPassword: inputChangePassword.GetOldPassword(),
			},
		}
		_, err = deps.Accounts.VerifyAuthenticatorsWithSpec(
			[]*authenticator.Info{info},
			spec,
			&accounts.VerifyAuthenticatorOptions{
				UserID:            info.UserID,
				AuthenticatorType: info.Type,
				// Omit Stage and AuthenticationType
				// so that it does not generate authentication failed event.
			},
		)
		if err != nil {
			return nil, err
		}

		changed, newInfo, err := deps.Accounts.UpdateAuthenticatorWithSpec(info, &authenticator.Spec{
			Password: &authenticator.PasswordSpec{
				PlainPassword: inputChangePassword.GetNewPassword(),
			},
		})
		if err != nil {
			return nil, err
		}

		if changed {
			return workflow.NewNodeSimple(&NodeDoUpdateAuthenticator{
				Authenticator: newInfo,
			}), nil
		}
		return workflow.NewNodeSimple(&NodeChangePasswordEnd{}), nil
	}
	return nil, workflow.ErrIncompatibleInput
}

func (n *NodeChangePassword) OutputData(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) (interface{}, error) {
	return map[string]interface{}{}, nil
}

func (n *NodeChangePassword) getPasswordAuthenticator(deps *workflow.Dependencies) (*authenticator.Info, error) {
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
