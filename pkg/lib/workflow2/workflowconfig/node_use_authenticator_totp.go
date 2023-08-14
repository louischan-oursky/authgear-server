package workflowconfig

import (
	"context"

	"github.com/authgear/authgear-server/pkg/api/model"
	"github.com/authgear/authgear-server/pkg/lib/authn"
	"github.com/authgear/authgear-server/pkg/lib/authn/authenticator"
	"github.com/authgear/authgear-server/pkg/lib/config"
	"github.com/authgear/authgear-server/pkg/lib/facade"
	workflow "github.com/authgear/authgear-server/pkg/lib/workflow2"
)

func init() {
	workflow.RegisterNode(&NodeUseAuthenticatorTOTP{})
}

type NodeUseAuthenticatorTOTP struct {
	UserID         string                              `json:"user_id,omitempty"`
	Authentication config.WorkflowAuthenticationMethod `json:"authentication,omitempty"`
}

var _ workflow.NodeSimple = &NodeUseAuthenticatorTOTP{}
var _ workflow.Milestone = &NodeUseAuthenticatorTOTP{}
var _ MilestoneAuthenticationMethod = &NodeUseAuthenticatorTOTP{}
var _ workflow.InputReactor = &NodeUseAuthenticatorTOTP{}

func (*NodeUseAuthenticatorTOTP) Kind() string {
	return "workflowconfig.NodeUseAuthenticatorTOTP"
}

func (*NodeUseAuthenticatorTOTP) Milestone() {}
func (n *NodeUseAuthenticatorTOTP) MilestoneAuthenticationMethod() config.WorkflowAuthenticationMethod {
	return n.Authentication
}

func (*NodeUseAuthenticatorTOTP) CanReactTo(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) ([]workflow.Input, error) {
	return []workflow.Input{&InputTakeTOTP{}}, nil
}

func (n *NodeUseAuthenticatorTOTP) ReactTo(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows, input workflow.Input) (*workflow.Node, error) {
	var inputTakeTOTP inputTakeTOTP
	if workflow.AsInput(input, &inputTakeTOTP) {
		as, err := deps.Authenticators.List(
			n.UserID,
			authenticator.KeepKind(n.Authentication.AuthenticatorKind()),
			authenticator.KeepType(model.AuthenticatorTypeTOTP),
		)
		if err != nil {
			return nil, err
		}

		code := inputTakeTOTP.GetCode()
		spec := &authenticator.Spec{
			TOTP: &authenticator.TOTPSpec{
				Code: code,
			},
		}

		info, _, err := deps.Authenticators.VerifyOneWithSpec(
			as,
			spec,
			&facade.VerifyOptions{
				AuthenticationDetails: facade.NewAuthenticationDetails(
					n.UserID,
					authn.AuthenticationStageFromAuthenticationMethod(n.Authentication),
					authn.AuthenticationTypeTOTP,
				),
			},
		)
		if err != nil {
			return nil, err
		}

		return workflow.NewNodeSimple(&NodeDidVerifyAuthenticator{
			Authenticator: info,
		}), nil
	}

	return nil, workflow.ErrIncompatibleInput
}
