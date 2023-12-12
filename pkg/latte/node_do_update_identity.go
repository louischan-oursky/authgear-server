package latte

import (
	"context"

	"github.com/authgear/authgear-server/pkg/api/event"
	"github.com/authgear/authgear-server/pkg/api/event/nonblocking"
	"github.com/authgear/authgear-server/pkg/api/model"
	"github.com/authgear/authgear-server/pkg/lib/accounts"
	"github.com/authgear/authgear-server/pkg/lib/authn/identity"
	"github.com/authgear/authgear-server/pkg/lib/workflow"
	"github.com/authgear/authgear-server/pkg/util/accesscontrol"
)

func init() {
	workflow.RegisterNode(&NodeDoUpdateIdentity{})
}

type NodeDoUpdateIdentity struct {
	IdentityBeforeUpdate *identity.Info                  `json:"identity_before_update"`
	Changes              *accounts.UpdateIdentityChanges `json:"changes,omitempty"`
}

func (n *NodeDoUpdateIdentity) Kind() string {
	return "latte.NodeDoUpdateIdentity"
}

func (n *NodeDoUpdateIdentity) GetEffects(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) (effs []workflow.Effect, err error) {
	return []workflow.Effect{
		workflow.RunEffect(func(ctx context.Context, deps *workflow.Dependencies) error {
			err := deps.AccountWriter.UpdateIdentity(n.Changes.UpdatedIdentity)
			if err != nil {
				return err
			}

			if n.Changes.UpdatedUser != nil {
				err = deps.AccountWriter.UpdateUser(n.Changes.UpdatedUser)
				if err != nil {
					return err
				}
			}

			for _, c := range n.Changes.NewVerifiedClaims {
				err = deps.AccountWriter.CreateVerifiedClaim(c)
				if err != nil {
					return err
				}
			}

			for _, c := range n.Changes.RemovedVerifiedClaims {
				err = deps.AccountWriter.DeleteVerifiedClaim(c)
				if err != nil {
					return err
				}
			}

			return nil
		}),
		workflow.OnCommitEffect(func(ctx context.Context, deps *workflow.Dependencies) error {
			userModel, err := deps.Users.Get(n.Changes.UpdatedIdentity.UserID, accesscontrol.RoleGreatest)
			if err != nil {
				return err
			}

			isAdminAPI := false
			var e event.NonBlockingPayload
			switch n.Changes.UpdatedIdentity.Type {
			case model.IdentityTypeLoginID:
				loginIDType := n.Changes.UpdatedIdentity.LoginID.LoginIDType
				if payload, ok := nonblocking.NewIdentityLoginIDUpdatedEventPayloadUserModel(
					*userModel,
					n.Changes.UpdatedIdentity.ToModel(),
					n.IdentityBeforeUpdate.ToModel(),
					string(loginIDType),
					isAdminAPI,
				); ok {
					e = payload
				}
			}

			if e != nil {
				err := deps.NonBlockingEvents.DispatchEvent(e)
				if err != nil {
					return err
				}
			}

			return nil
		}),
	}, nil
}

func (*NodeDoUpdateIdentity) CanReactTo(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) ([]workflow.Input, error) {
	return nil, workflow.ErrEOF
}

func (*NodeDoUpdateIdentity) ReactTo(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows, input workflow.Input) (*workflow.Node, error) {
	return nil, workflow.ErrIncompatibleInput
}

func (n *NodeDoUpdateIdentity) OutputData(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) (interface{}, error) {
	return nil, nil
}
