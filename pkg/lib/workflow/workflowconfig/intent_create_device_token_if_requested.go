package workflowconfig

import (
	"context"

	"github.com/authgear/authgear-server/pkg/lib/workflow"
	"github.com/authgear/authgear-server/pkg/util/validation"
)

func init() {
	workflow.RegisterPrivateIntent(&IntentCreateDeviceTokenIfRequested{})
}

var IntentCreateDeviceTokenIfRequestedSchema = validation.NewSimpleSchema(`{}`)

type IntentCreateDeviceTokenIfRequested struct {
	UserID string `json:"user_id,omitempty"`
}

var _ MilestoneDoCreateDeviceTokenIfRequested = &IntentCreateDeviceTokenIfRequested{}

func (*IntentCreateDeviceTokenIfRequested) Milestone()                               {}
func (*IntentCreateDeviceTokenIfRequested) MilestoneDoCreateDeviceTokenIfRequested() {}

var _ workflow.Intent = &IntentCreateDeviceTokenIfRequested{}

func (*IntentCreateDeviceTokenIfRequested) Kind() string {
	return "workflowconfig.IntentCreateDeviceTokenIfRequested"
}

func (*IntentCreateDeviceTokenIfRequested) JSONSchema() *validation.SimpleSchema {
	return IntentCreateDeviceTokenIfRequestedSchema
}

func (*IntentCreateDeviceTokenIfRequested) CanReactTo(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) ([]workflow.Input, error) {
	if len(workflows.Nearest.Nodes) == 0 {
		// Take the previous input.
		return nil, nil
	}
	return nil, workflow.ErrEOF
}

func (i *IntentCreateDeviceTokenIfRequested) ReactTo(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows, input workflow.Input) (*workflow.Node, error) {
	if len(workflows.Nearest.Nodes) == 0 {
		var inputDeviceTokenRequested inputDeviceTokenRequested
		ok := workflow.AsInput(input, &inputDeviceTokenRequested)

		if !ok {
			// We consider this as not requested.
			// End this workflow.
			return workflow.NewNodeSimple(&NodeSentinel{}), nil
		}

		requested := inputDeviceTokenRequested.GetDeviceTokenRequested()
		if !requested {
			// Simply end this workflow.
			return workflow.NewNodeSimple(&NodeSentinel{}), nil
		}

		n, err := NewNodeDoCreateDeviceToken(deps, &NodeDoCreateDeviceToken{
			UserID: i.UserID,
		})
		if err != nil {
			return nil, err
		}

		return workflow.NewNodeSimple(n), nil
	}

	return nil, workflow.ErrIncompatibleInput
}

func (*IntentCreateDeviceTokenIfRequested) GetEffects(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) ([]workflow.Effect, error) {
	return nil, nil
}

func (*IntentCreateDeviceTokenIfRequested) OutputData(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) (interface{}, error) {
	return nil, nil
}
