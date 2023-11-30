package latte

import (
	"context"
	"errors"

	"github.com/authgear/authgear-server/pkg/api"
	"github.com/authgear/authgear-server/pkg/api/model"
	"github.com/authgear/authgear-server/pkg/lib/authn/identity"
	"github.com/authgear/authgear-server/pkg/lib/workflow"
)

func init() {
	workflow.RegisterNode(&NodeChangeEmail{})
}

type NodeChangeEmail struct {
	UserID               string         `json:"user_id,omitempty"`
	IdentityBeforeUpdate *identity.Info `json:"identity_before_update,omitempty"`
}

func (n *NodeChangeEmail) Kind() string {
	return "latte.NodeChangeEmail"
}

func (n *NodeChangeEmail) GetEffects(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) (effs []workflow.Effect, err error) {
	return nil, nil
}

func (n *NodeChangeEmail) CanReactTo(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) ([]workflow.Input, error) {
	return []workflow.Input{
		&InputTakeLoginID{},
	}, nil
}

func (n *NodeChangeEmail) ReactTo(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows, input workflow.Input) (*workflow.Node, error) {
	var inputTakeLoginID inputTakeLoginID

	switch {
	case workflow.AsInput(input, &inputTakeLoginID):
		loginID := inputTakeLoginID.GetLoginID()
		spec := &identity.Spec{
			Type: model.IdentityTypeLoginID,
			LoginID: &identity.LoginIDSpec{
				Type:  model.LoginIDKeyTypeEmail,
				Key:   string(model.LoginIDKeyTypeEmail),
				Value: loginID,
			},
		}

		// FIXME(workflow): retrieve dependency elsewhere
		u, err := deps.Accounts.GetUserByID(n.UserID)
		if err != nil {
			return nil, err
		}
		identities, err := deps.Accounts.ListIdentitiesOfUser(n.UserID)
		if err != nil {
			return nil, err
		}
		authenticators, err := deps.Accounts.ListAuthenticatorsOfUser(n.UserID)
		if err != nil {
			return nil, err
		}
		claims, err := deps.Accounts.ListVerifiedClaimsOfUser(n.UserID)
		if err != nil {
			return nil, err
		}

		changes, err := deps.Accounts.GetUpdateIdentityChanges(
			n.IdentityBeforeUpdate,
			spec,
			u,
			identities,
			authenticators,
			claims,
		)
		if err != nil {
			return nil, err
		}

		_, err = deps.Accounts.FindDuplicatedIdentity(changes.UpdatedIdentity)
		if err != nil {
			if errors.Is(err, identity.ErrIdentityAlreadyExists) {
				s1 := n.IdentityBeforeUpdate.ToSpec()
				s2 := changes.UpdatedIdentity.ToSpec()
				return nil, identityFillDetails(api.ErrDuplicatedIdentity, &s2, &s1)
			}
			return nil, err
		}

		return workflow.NewNodeSimple(&NodeDoUpdateIdentity{
			IdentityBeforeUpdate: n.IdentityBeforeUpdate,
			Changes:              changes,
		}), nil
	}
	return nil, workflow.ErrIncompatibleInput
}

func (n *NodeChangeEmail) OutputData(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) (interface{}, error) {
	return map[string]interface{}{}, nil
}
