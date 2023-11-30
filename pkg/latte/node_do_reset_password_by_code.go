package latte

import (
	"context"

	"github.com/authgear/authgear-server/pkg/lib/workflow"
)

func init() {
	workflow.RegisterNode(&NodeDoResetPasswordByCode{})
}

type NodeDoResetPasswordByCode struct {
	Code        string `json:"code"`
	NewPassword string `json:"new_password"`
}

func (n *NodeDoResetPasswordByCode) Kind() string {
	return "latte.NodeDoResetPasswordByCode"
}

func (n *NodeDoResetPasswordByCode) GetEffects(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) (effs []workflow.Effect, err error) {
	return []workflow.Effect{
		workflow.OnCommitEffect(func(ctx context.Context, deps *workflow.Dependencies) error {
			state, err := deps.ResetPassword.VerifyCode(n.Code)
			if err != nil {
				return err
			}

			// FIXME(workflow): retrieve dependency elsewhere
			authenticators, err := deps.Accounts.ListAuthenticatorsOfUser(state.UserID)
			if err != nil {
				return err
			}

			result, err := deps.Accounts.ResetPrimaryPassword(authenticators, state, n.NewPassword)
			if err != nil {
				return err
			}

			if result.MaybeUpdatedAuthenticator != nil {
				err = deps.AccountWriter.UpdateAuthenticator(result.MaybeUpdatedAuthenticator)
				if err != nil {
					return err
				}
			}

			if result.MaybeNewAuthenticator != nil {
				err = deps.AccountWriter.CreateAuthenticator(result.MaybeNewAuthenticator)
				if err != nil {
					return err
				}
			}

			for _, a := range result.RemovedAuthenticators {
				err = deps.AccountWriter.DeleteAuthenticator(a)
				if err != nil {
					return err
				}
			}

			return nil
		}),
	}, nil
}

func (*NodeDoResetPasswordByCode) CanReactTo(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) ([]workflow.Input, error) {
	return nil, workflow.ErrEOF
}

func (*NodeDoResetPasswordByCode) ReactTo(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows, input workflow.Input) (*workflow.Node, error) {
	return nil, workflow.ErrIncompatibleInput
}

func (n *NodeDoResetPasswordByCode) OutputData(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) (interface{}, error) {
	return nil, nil
}
