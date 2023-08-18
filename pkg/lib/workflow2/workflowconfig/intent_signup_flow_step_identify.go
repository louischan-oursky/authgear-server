package workflowconfig

import (
	"context"
	"fmt"

	"github.com/iawaknahc/jsonschema/pkg/jsonpointer"

	"github.com/authgear/authgear-server/pkg/api/model"
	"github.com/authgear/authgear-server/pkg/lib/authn/identity"
	"github.com/authgear/authgear-server/pkg/lib/authn/otp"
	"github.com/authgear/authgear-server/pkg/lib/config"
	workflow "github.com/authgear/authgear-server/pkg/lib/workflow2"
)

func init() {
	workflow.RegisterIntent(&IntentSignupFlowStepIdentify{})
}

type IntentSignupFlowStepIdentify struct {
	SignupFlow  string        `json:"signup_flow,omitempty"`
	JSONPointer jsonpointer.T `json:"json_pointer,omitempty"`
	StepID      string        `json:"step_id,omitempty"`
	UserID      string        `json:"user_id,omitempty"`
}

var _ WorkflowStep = &IntentSignupFlowStepIdentify{}

func (i *IntentSignupFlowStepIdentify) GetID() string {
	return i.StepID
}

func (i *IntentSignupFlowStepIdentify) GetJSONPointer() jsonpointer.T {
	return i.JSONPointer
}

var _ IntentSignupFlowStepVerifyTarget = &IntentSignupFlowStepIdentify{}

func (*IntentSignupFlowStepIdentify) GetVerifiableClaims(_ context.Context, _ *workflow.Dependencies, workflows workflow.Workflows) (map[model.ClaimName]string, error) {
	m, ok := workflow.FindMilestone[MilestoneDoCreateIdentity](workflows.Nearest)
	if !ok {
		return nil, fmt.Errorf("MilestoneDoCreateIdentity cannot be found in IntentSignupFlowStepIdentify")
	}
	info := m.MilestoneDoCreateIdentity()

	return info.IdentityAwareStandardClaims(), nil
}

func (*IntentSignupFlowStepIdentify) GetPurpose(_ context.Context, _ *workflow.Dependencies, _ workflow.Workflows) otp.Purpose {
	return otp.PurposeVerification
}

func (*IntentSignupFlowStepIdentify) GetMessageType(_ context.Context, _ *workflow.Dependencies, _ workflow.Workflows) otp.MessageType {
	return otp.MessageTypeVerification
}

var _ IntentSignupFlowStepAuthenticateTarget = &IntentSignupFlowStepIdentify{}

func (n *IntentSignupFlowStepIdentify) GetOOBOTPClaims(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) (map[model.ClaimName]string, error) {
	return n.GetVerifiableClaims(ctx, deps, workflows)
}

var _ workflow.Intent = &IntentSignupFlowStepIdentify{}
var _ workflow.Boundary = &IntentSignupFlowStepIdentify{}

func (*IntentSignupFlowStepIdentify) Kind() string {
	return "workflowconfig.IntentSignupFlowStepIdentify"
}

func (i *IntentSignupFlowStepIdentify) Boundary() string {
	return i.JSONPointer.String()
}

func (i *IntentSignupFlowStepIdentify) CanReactTo(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) (workflow.InputSchema, error) {
	current, err := signupFlowCurrent(deps, i.SignupFlow, i.JSONPointer)
	if err != nil {
		return nil, err
	}
	step := i.step(current)

	// Let the input to select which identification method to use.
	if len(workflows.Nearest.Nodes) == 0 {
		return &InputSchemaSignupFlowStepIdentify{
			OneOf: step.OneOf,
		}, nil
	}

	_, identityCreated := workflow.FindMilestone[MilestoneDoCreateIdentity](workflows.Nearest)
	_, standardAttributesPopulated := workflow.FindMilestone[MilestoneDoPopulateStandardAttributes](workflows.Nearest)
	_, nestedStepHandled := workflow.FindMilestone[MilestoneNestedSteps](workflows.Nearest)

	switch {
	case identityCreated && !standardAttributesPopulated && !nestedStepHandled:
		// Populate standard attributes
		return nil, nil
	case identityCreated && standardAttributesPopulated && !nestedStepHandled:
		// Handle nested steps.
		return nil, nil
	default:
		return nil, workflow.ErrEOF
	}
}

func (i *IntentSignupFlowStepIdentify) ReactTo(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows, input workflow.Input) (*workflow.Node, error) {
	current, err := signupFlowCurrent(deps, i.SignupFlow, i.JSONPointer)
	if err != nil {
		return nil, err
	}
	step := i.step(current)

	if len(workflows.Nearest.Nodes) == 0 {
		var inputTakeIdentificationMethod inputTakeIdentificationMethod
		if workflow.AsInput(input, &inputTakeIdentificationMethod) {
			identification := inputTakeIdentificationMethod.GetIdentificationMethod()

			switch identification {
			case config.WorkflowIdentificationMethodEmail:
				fallthrough
			case config.WorkflowIdentificationMethodPhone:
				fallthrough
			case config.WorkflowIdentificationMethodUsername:
				return workflow.NewNodeSimple(&NodeCreateIdentityLoginID{
					UserID:         i.UserID,
					Identification: identification,
				}), nil
			case config.WorkflowIdentificationMethodOAuth:
				// FIXME(workflow): handle oauth
			case config.WorkflowIdentificationMethodPasskey:
				// FIXME(workflow): handle passkey
			case config.WorkflowIdentificationMethodSiwe:
				// FIXME(workflow): handle siwe
			}
		}
		return nil, workflow.ErrIncompatibleInput
	}

	_, identityCreated := workflow.FindMilestone[MilestoneDoCreateIdentity](workflows.Nearest)
	_, standardAttributesPopulated := workflow.FindMilestone[MilestoneDoPopulateStandardAttributes](workflows.Nearest)
	_, nestedStepHandled := workflow.FindMilestone[MilestoneNestedSteps](workflows.Nearest)

	switch {
	case identityCreated && !standardAttributesPopulated && !nestedStepHandled:
		iden := i.identityInfo(workflows.Nearest)
		return workflow.NewNodeSimple(&NodeDoPopulateStandardAttributes{
			Identity: iden,
		}), nil
	case identityCreated && standardAttributesPopulated && !nestedStepHandled:
		identification := i.identificationMethod(workflows.Nearest)
		return workflow.NewSubWorkflow(&IntentSignupFlowSteps{
			SignupFlow:  i.SignupFlow,
			JSONPointer: i.jsonPointer(step, identification),
			UserID:      i.UserID,
		}), nil
	default:
		return nil, workflow.ErrIncompatibleInput
	}
}

func (*IntentSignupFlowStepIdentify) step(o config.WorkflowObject) *config.WorkflowSignupFlowStep {
	step, ok := o.(*config.WorkflowSignupFlowStep)
	if !ok {
		panic(fmt.Errorf("workflow: workflow object is %T", o))
	}

	return step
}

func (*IntentSignupFlowStepIdentify) identificationMethod(w *workflow.Workflow) config.WorkflowIdentificationMethod {
	m, ok := workflow.FindMilestone[MilestoneIdentificationMethod](w)
	if !ok {
		panic(fmt.Errorf("workflow: identification method not yet selected"))
	}

	im := m.MilestoneIdentificationMethod()

	return im
}

func (i *IntentSignupFlowStepIdentify) jsonPointer(step *config.WorkflowSignupFlowStep, im config.WorkflowIdentificationMethod) jsonpointer.T {
	for idx, branch := range step.OneOf {
		branch := branch
		if branch.Identification == im {
			return JSONPointerForOneOf(i.JSONPointer, idx)
		}
	}

	panic(fmt.Errorf("workflow: selected identification method is not allowed"))
}

func (*IntentSignupFlowStepIdentify) identityInfo(w *workflow.Workflow) *identity.Info {
	m, ok := workflow.FindMilestone[MilestoneDoCreateIdentity](w)
	if !ok {
		panic(fmt.Errorf("MilestoneDoCreateIdentity cannot be found in IntentSignupFlowStepIdentify"))
	}
	info := m.MilestoneDoCreateIdentity()
	return info
}