package latte

import (
	"context"

	"github.com/authgear/authgear-server/pkg/lib/authn/identity"
	"github.com/authgear/authgear-server/pkg/lib/authn/user"
	"github.com/authgear/authgear-server/pkg/lib/workflow"
)

func init() {
	workflow.RegisterNode(&NodePopulateStandardAttributes{})
}

type NodePopulateStandardAttributes struct {
	Identity    *identity.Info `json:"identity,omitempty"`
	UpdatedUser *user.User     `json:"updated_user,omitempty"`
}

func NewNodePopulateStandardAttributes(ctx context.Context, deps *workflow.Dependencies, info *identity.Info) (*NodePopulateStandardAttributes, error) {
	// FIXME(workflow): retrieve dependency elsewhere
	u, err := deps.Accounts.GetUserByID(info.UserID)
	if err != nil {
		return nil, err
	}
	u = deps.Accounts.PopulateStandardAttribute(u, info)
	return &NodePopulateStandardAttributes{
		Identity:    info,
		UpdatedUser: u,
	}, nil
}

func (n *NodePopulateStandardAttributes) Kind() string {
	return "latte.NodePopulateStandardAttributes"
}

func (n *NodePopulateStandardAttributes) GetEffects(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) (effs []workflow.Effect, err error) {
	return []workflow.Effect{
		workflow.RunEffect(func(ctx context.Context, deps *workflow.Dependencies) error {
			return deps.AccountWriter.UpdateUser(n.UpdatedUser)
		}),
	}, nil
}

func (*NodePopulateStandardAttributes) CanReactTo(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) ([]workflow.Input, error) {
	return nil, workflow.ErrEOF
}

func (*NodePopulateStandardAttributes) ReactTo(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows, input workflow.Input) (*workflow.Node, error) {
	return nil, workflow.ErrIncompatibleInput
}

func (n *NodePopulateStandardAttributes) OutputData(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) (interface{}, error) {
	return nil, nil
}
