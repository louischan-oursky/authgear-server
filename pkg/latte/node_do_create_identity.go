package latte

import (
	"context"

	"github.com/authgear/authgear-server/pkg/lib/accounts"
	"github.com/authgear/authgear-server/pkg/lib/workflow"
)

func init() {
	workflow.RegisterNode(&NodeDoCreateIdentity{})
}

type NodeDoCreateIdentity struct {
	NewIdentityChanges *accounts.NewIdentityChanges `json:"new_identity_changes,omitempty"`
}

func (n *NodeDoCreateIdentity) Kind() string {
	return "latte.NodeDoCreateIdentity"
}

func (n *NodeDoCreateIdentity) GetEffects(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) (effs []workflow.Effect, err error) {
	return []workflow.Effect{
		workflow.RunEffect(func(ctx context.Context, deps *workflow.Dependencies) error {
			if n.NewIdentityChanges.UpdatedUser != nil {
				err := deps.AccountWriter.UpdateUser(n.NewIdentityChanges.UpdatedUser)
				if err != nil {
					return err
				}
			}
			err := deps.AccountWriter.CreateIdentity(n.NewIdentityChanges.NewIdentity)
			if err != nil {
				return err
			}
			for _, c := range n.NewIdentityChanges.NewVerifiedClaims {
				err := deps.AccountWriter.CreateVerifiedClaim(c)
				if err != nil {
					return err
				}
			}

			return nil
		}),
	}, nil
}

func (*NodeDoCreateIdentity) CanReactTo(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) ([]workflow.Input, error) {
	return nil, workflow.ErrEOF
}

func (*NodeDoCreateIdentity) ReactTo(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows, input workflow.Input) (*workflow.Node, error) {
	return nil, workflow.ErrIncompatibleInput
}

func (n *NodeDoCreateIdentity) OutputData(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) (interface{}, error) {
	return nil, nil
}
