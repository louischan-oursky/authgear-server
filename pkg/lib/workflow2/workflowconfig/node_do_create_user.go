package workflowconfig

import (
	"context"

	workflow "github.com/authgear/authgear-server/pkg/lib/workflow2"
)

func init() {
	workflow.RegisterNode(&NodeDoCreateUser{})
}

type NodeDoCreateUser struct {
	UserID string `json:"user_id"`
}

var _ workflow.NodeSimple = &NodeDoCreateUser{}
var _ workflow.Milestone = &NodeDoCreateUser{}
var _ MilestoneDoUseUser = &NodeDoCreateUser{}
var _ MilestoneDoCreateUser = &NodeDoCreateUser{}
var _ workflow.EffectGetter = &NodeDoCreateUser{}

func (n *NodeDoCreateUser) Kind() string {
	return "workflowconfig.NodeDoCreateUser"
}

func (*NodeDoCreateUser) Milestone()                      {}
func (n *NodeDoCreateUser) MilestoneDoUseUser() string    { return n.UserID }
func (n *NodeDoCreateUser) MilestoneDoCreateUser() string { return n.UserID }

func (n *NodeDoCreateUser) GetEffects(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) (effs []workflow.Effect, err error) {
	return []workflow.Effect{
		workflow.RunEffect(func(ctx context.Context, deps *workflow.Dependencies) error {
			_, err := deps.Users.Create(n.UserID)
			return err
		}),
	}, nil
}