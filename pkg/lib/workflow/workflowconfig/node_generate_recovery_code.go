package workflowconfig

import (
	"context"

	"github.com/authgear/authgear-server/pkg/lib/workflow"
)

func init() {
	workflow.RegisterNode(&NodeGenerateRecoveryCode{})
}

type NodeGenerateRecoveryCode struct {
	UserID        string   `json:"user_id,omitempty"`
	RecoveryCodes []string `json:"recovery_codes,omitempty"`
}

func NewNodeGenerateRecoveryCode(deps *workflow.Dependencies, n *NodeGenerateRecoveryCode) *NodeGenerateRecoveryCode {
	n.RecoveryCodes = deps.MFA.GenerateRecoveryCodes()
	return n
}

func (*NodeGenerateRecoveryCode) Kind() string {
	return "workflowconfig.NodeGenerateRecoveryCode"
}

func (*NodeGenerateRecoveryCode) GetEffects(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) (effs []workflow.Effect, err error) {
	return nil, nil
}

func (*NodeGenerateRecoveryCode) CanReactTo(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) ([]workflow.Input, error) {
	return []workflow.Input{
		&InputConfirmRecoveryCode{},
	}, nil
}

func (n *NodeGenerateRecoveryCode) ReactTo(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows, input workflow.Input) (*workflow.Node, error) {
	var inputConfirmRecoveryCode inputConfirmRecoveryCode
	if workflow.AsInput(input, &inputConfirmRecoveryCode) {
		return workflow.NewNodeSimple(&NodeDoReplaceRecoveryCode{
			UserID:        n.UserID,
			RecoveryCodes: n.RecoveryCodes,
		}), nil
	}

	return nil, workflow.ErrIncompatibleInput
}

func (n *NodeGenerateRecoveryCode) OutputData(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) (interface{}, error) {
	return map[string]interface{}{
		"recovery_codes": n.RecoveryCodes,
	}, nil
}