package workflowconfig

import (
	"context"
	"fmt"

	"github.com/iawaknahc/jsonschema/pkg/jsonpointer"

	"github.com/authgear/authgear-server/pkg/lib/config"
	workflow "github.com/authgear/authgear-server/pkg/lib/workflow2"
)

func init() {
	workflow.RegisterIntent(&IntentSignupFlowSteps{})
}

type IntentSignupFlowSteps struct {
	SignupFlow  string        `json:"signup_flow,omitempty"`
	JSONPointer jsonpointer.T `json:"json_pointer,omitempty"`
	UserID      string        `json:"user_id,omitempty"`
}

var _ workflow.Intent = &IntentSignupFlowSteps{}
var _ workflow.Milestone = &IntentSignupFlowSteps{}
var _ MilestoneNestedSteps = &IntentSignupFlowSteps{}

func (*IntentSignupFlowSteps) Kind() string {
	return "workflowconfig.IntentSignupFlowSteps"
}

func (*IntentSignupFlowSteps) Milestone()            {}
func (*IntentSignupFlowSteps) MilestoneNestedSteps() {}

func (i *IntentSignupFlowSteps) CanReactTo(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows) (workflow.InputSchema, error) {
	current, err := signupFlowCurrent(deps, i.SignupFlow, i.JSONPointer)
	if err != nil {
		return nil, err
	}

	steps := i.steps(current)
	if len(workflows.Nearest.Nodes) < len(steps) {
		return nil, nil
	}

	return nil, workflow.ErrEOF
}

func (i *IntentSignupFlowSteps) ReactTo(ctx context.Context, deps *workflow.Dependencies, workflows workflow.Workflows, _ workflow.Input) (*workflow.Node, error) {
	current, err := signupFlowCurrent(deps, i.SignupFlow, i.JSONPointer)
	if err != nil {
		return nil, err
	}

	steps := i.steps(current)
	nextStepIndex := len(workflows.Nearest.Nodes)
	step := steps[nextStepIndex].(*config.WorkflowSignupFlowStep)

	switch step.Type {
	case config.WorkflowSignupFlowStepTypeIdentify:
		return workflow.NewSubWorkflow(&IntentSignupFlowStepIdentify{
			SignupFlow:  i.SignupFlow,
			StepID:      step.ID,
			JSONPointer: JSONPointerForStep(i.JSONPointer, nextStepIndex),
			UserID:      i.UserID,
		}), nil
	case config.WorkflowSignupFlowStepTypeVerify:
		return workflow.NewSubWorkflow(&IntentSignupFlowStepVerify{
			SignupFlow:  i.SignupFlow,
			StepID:      step.ID,
			JSONPointer: JSONPointerForStep(i.JSONPointer, nextStepIndex),
			UserID:      i.UserID,
		}), nil
	case config.WorkflowSignupFlowStepTypeAuthenticate:
		return workflow.NewSubWorkflow(&IntentSignupFlowStepAuthenticate{
			SignupFlow:  i.SignupFlow,
			StepID:      step.ID,
			JSONPointer: JSONPointerForStep(i.JSONPointer, nextStepIndex),
			UserID:      i.UserID,
		}), nil
	case config.WorkflowSignupFlowStepTypeRecoveryCode:
		return workflow.NewSubWorkflow(&IntentSignupFlowStepRecoveryCode{
			SignupFlow:  i.SignupFlow,
			StepID:      step.ID,
			JSONPointer: JSONPointerForStep(i.JSONPointer, nextStepIndex),
			UserID:      i.UserID,
		}), nil
	case config.WorkflowSignupFlowStepTypeUserProfile:
		return workflow.NewSubWorkflow(&IntentSignupFlowStepUserProfile{
			SignupFlow:  i.SignupFlow,
			StepID:      step.ID,
			JSONPointer: JSONPointerForStep(i.JSONPointer, nextStepIndex),
			UserID:      i.UserID,
		}), nil
	}

	return nil, workflow.ErrIncompatibleInput
}

func (i *IntentSignupFlowSteps) steps(o config.WorkflowObject) []config.WorkflowObject {
	steps, ok := o.GetSteps()
	if !ok {
		panic(fmt.Errorf("workflow: workflow object does not have steps %T", o))
	}

	return steps
}