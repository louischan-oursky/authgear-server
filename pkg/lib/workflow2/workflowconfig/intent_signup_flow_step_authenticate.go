package workflowconfig

import (
	"context"
	"fmt"

	"github.com/iawaknahc/jsonschema/pkg/jsonpointer"

	"github.com/authgear/authgear-server/pkg/api/model"
	"github.com/authgear/authgear-server/pkg/lib/authn/otp"
	"github.com/authgear/authgear-server/pkg/lib/config"
	workflow "github.com/authgear/authgear-server/pkg/lib/workflow2"
)

type IntentSignupFlowStepAuthenticateTarget interface {
	GetOOBOTPClaims(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) (map[model.ClaimName]string, error)
}

func init() {
	workflow.RegisterIntent(&IntentSignupFlowStepAuthenticate{})
}

type IntentSignupFlowStepAuthenticateData struct {
	PasswordPolicy *PasswordPolicy `json:"password_policy,omitempty"`
}

func (m IntentSignupFlowStepAuthenticateData) Data() {}

type IntentSignupFlowStepAuthenticate struct {
	SignupFlow  string        `json:"signup_flow,omitempty"`
	JSONPointer jsonpointer.T `json:"json_pointer,omitempty"`
	StepID      string        `json:"step_id,omitempty"`
	UserID      string        `json:"user_id,omitempty"`
}

var _ WorkflowStep = &IntentSignupFlowStepAuthenticate{}

func (i *IntentSignupFlowStepAuthenticate) GetID() string {
	return i.StepID
}

func (i *IntentSignupFlowStepAuthenticate) GetJSONPointer() jsonpointer.T {
	return i.JSONPointer
}

var _ IntentSignupFlowStepVerifyTarget = &IntentSignupFlowStepAuthenticate{}

func (*IntentSignupFlowStepAuthenticate) GetVerifiableClaims(_ context.Context, _ *workflow.Dependencies, workflows workflow.Workflows) (map[model.ClaimName]string, error) {
	m, ok := workflow.FindMilestone[MilestoneDoCreateAuthenticator](workflows.Nearest)
	if !ok {
		return nil, fmt.Errorf("MilestoneDoCreateAuthenticator cannot be found in IntentSignupFlowStepAuthenticate")
	}

	info := m.MilestoneDoCreateAuthenticator()

	return info.StandardClaims(), nil
}

func (*IntentSignupFlowStepAuthenticate) GetPurpose(_ context.Context, _ *workflow.Dependencies, _ workflow.Workflows) otp.Purpose {
	return otp.PurposeOOBOTP
}

func (i *IntentSignupFlowStepAuthenticate) GetMessageType(_ context.Context, _ *workflow.Dependencies, workflows workflow.Workflows) otp.MessageType {
	authenticationMethod := i.authenticationMethod(workflows)
	switch authenticationMethod {
	case config.WorkflowAuthenticationMethodPrimaryOOBOTPEmail:
		return otp.MessageTypeSetupPrimaryOOB
	case config.WorkflowAuthenticationMethodPrimaryOOBOTPSMS:
		return otp.MessageTypeSetupPrimaryOOB
	case config.WorkflowAuthenticationMethodSecondaryOOBOTPEmail:
		return otp.MessageTypeSetupSecondaryOOB
	case config.WorkflowAuthenticationMethodSecondaryOOBOTPSMS:
		return otp.MessageTypeSetupSecondaryOOB
	default:
		panic(fmt.Errorf("workflow: unexpected authentication method: %v", authenticationMethod))
	}
}

var _ workflow.Intent = &IntentSignupFlowStepAuthenticate{}
var _ workflow.Boundary = &IntentSignupFlowStepAuthenticate{}
var _ workflow.DataOutputer = &IntentSignupFlowStepAuthenticate{}

func (*IntentSignupFlowStepAuthenticate) Kind() string {
	return "workflowconfig.IntentSignupFlowStepAuthenticate"
}

func (i *IntentSignupFlowStepAuthenticate) Boundary() string {
	return i.JSONPointer.String()
}

func (i *IntentSignupFlowStepAuthenticate) CanReactTo(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) (workflow.InputSchema, error) {
	// Let the input to select which authentication method to use.
	if len(workflows.Nearest.Nodes) == 0 {
		current, err := signupFlowCurrent(deps, i.SignupFlow, i.JSONPointer)
		if err != nil {
			return nil, err
		}
		step := i.step(current)
		return &InputSchemaSignupFlowStepAuthenticate{
			OneOf: step.OneOf,
		}, nil
	}

	_, authenticatorCreated := workflow.FindMilestone[MilestoneDoCreateAuthenticator](workflows.Nearest)
	_, nestedStepsHandled := workflow.FindMilestone[MilestoneNestedSteps](workflows.Nearest)

	switch {
	case authenticatorCreated && !nestedStepsHandled:
		// Handle nested steps.
		return nil, nil
	default:
		return nil, workflow.ErrEOF
	}
}

func (i *IntentSignupFlowStepAuthenticate) ReactTo(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows, input workflow.Input) (*workflow.Node, error) {
	current, err := signupFlowCurrent(deps, i.SignupFlow, i.JSONPointer)
	if err != nil {
		return nil, err
	}
	step := i.step(current)

	if len(workflows.Nearest.Nodes) == 0 {
		var inputTakeAuthenticationMethod inputTakeAuthenticationMethod
		if workflow.AsInput(input, &inputTakeAuthenticationMethod) {

			authentication := inputTakeAuthenticationMethod.GetAuthenticationMethod()
			idx := i.checkAuthenticationMethod(deps, step, authentication)

			switch authentication {
			case config.WorkflowAuthenticationMethodPrimaryPassword:
				fallthrough
			case config.WorkflowAuthenticationMethodSecondaryPassword:
				return workflow.NewNodeSimple(&NodeCreateAuthenticatorPassword{
					UserID:         i.UserID,
					Authentication: authentication,
				}), nil
			case config.WorkflowAuthenticationMethodPrimaryPasskey:
				// FIXME(workflow): create primary passkey
			case config.WorkflowAuthenticationMethodPrimaryOOBOTPEmail:
				fallthrough
			case config.WorkflowAuthenticationMethodSecondaryOOBOTPEmail:
				fallthrough
			case config.WorkflowAuthenticationMethodPrimaryOOBOTPSMS:
				fallthrough
			case config.WorkflowAuthenticationMethodSecondaryOOBOTPSMS:
				return workflow.NewNodeSimple(&NodeCreateAuthenticatorOOBOTP{
					SignupFlow:     i.SignupFlow,
					JSONPointer:    JSONPointerForOneOf(i.JSONPointer, idx),
					UserID:         i.UserID,
					Authentication: authentication,
				}), nil
			case config.WorkflowAuthenticationMethodSecondaryTOTP:
				node, err := NewNodeCreateAuthenticatorTOTP(deps, &NodeCreateAuthenticatorTOTP{
					UserID:         i.UserID,
					Authentication: authentication,
				})
				if err != nil {
					return nil, err
				}
				return workflow.NewNodeSimple(node), nil
			}
		}
		return nil, workflow.ErrIncompatibleInput
	}

	_, authenticatorCreated := workflow.FindMilestone[MilestoneDoCreateAuthenticator](workflows.Nearest)
	_, nestedStepsHandled := workflow.FindMilestone[MilestoneNestedSteps](workflows.Nearest)

	switch {
	case authenticatorCreated && !nestedStepsHandled:
		authentication := i.authenticationMethod(workflows)
		return workflow.NewSubWorkflow(&IntentSignupFlowSteps{
			SignupFlow:  i.SignupFlow,
			JSONPointer: i.jsonPointer(step, authentication),
			UserID:      i.UserID,
		}), nil
	default:
		return nil, workflow.ErrIncompatibleInput
	}
}

func (i *IntentSignupFlowStepAuthenticate) OutputData(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) (workflow.Data, error) {
	return IntentSignupFlowStepAuthenticateData{
		PasswordPolicy: NewPasswordPolicy(deps.Config.Authenticator.Password.Policy),
	}, nil
}

func (*IntentSignupFlowStepAuthenticate) step(o config.WorkflowObject) *config.WorkflowSignupFlowStep {
	step, ok := o.(*config.WorkflowSignupFlowStep)
	if !ok {
		panic(fmt.Errorf("workflow: workflow object is %T", o))
	}

	return step
}

func (i *IntentSignupFlowStepAuthenticate) checkAuthenticationMethod(deps *workflow.Dependencies, step *config.WorkflowSignupFlowStep, am config.WorkflowAuthenticationMethod) (idx int) {
	idx = -1

	for index, branch := range step.OneOf {
		branch := branch
		if am == branch.Authentication {
			idx = index
		}
	}

	if idx >= 0 {
		return
	}

	panic(fmt.Errorf("the input schema should have ensured index can always be found"))
}

func (*IntentSignupFlowStepAuthenticate) authenticationMethod(workflows workflow.Workflows) config.WorkflowAuthenticationMethod {
	m, ok := workflow.FindMilestone[MilestoneAuthenticationMethod](workflows.Nearest)
	if !ok {
		panic(fmt.Errorf("workflow: authentication method not yet selected"))
	}

	am := m.MilestoneAuthenticationMethod()

	return am
}

func (i *IntentSignupFlowStepAuthenticate) jsonPointer(step *config.WorkflowSignupFlowStep, am config.WorkflowAuthenticationMethod) jsonpointer.T {
	for idx, branch := range step.OneOf {
		branch := branch
		if branch.Authentication == am {
			return JSONPointerForOneOf(i.JSONPointer, idx)
		}
	}

	panic(fmt.Errorf("workflow: selected identification method is not allowed"))
}