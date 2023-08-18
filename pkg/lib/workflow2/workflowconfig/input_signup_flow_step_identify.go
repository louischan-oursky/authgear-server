package workflowconfig

import (
	"encoding/json"

	"github.com/authgear/authgear-server/pkg/lib/config"
	workflow "github.com/authgear/authgear-server/pkg/lib/workflow2"
	"github.com/authgear/authgear-server/pkg/util/validation"
)

type InputSchemaSignupFlowStepIdentify struct {
	OneOf []*config.WorkflowSignupFlowOneOf
}

var _ workflow.InputSchema = &InputSchemaSignupFlowStepIdentify{}

func (i *InputSchemaSignupFlowStepIdentify) SchemaBuilder() validation.SchemaBuilder {
	oneOf := []validation.SchemaBuilder{}

	for _, branch := range i.OneOf {
		branch := branch

		b := validation.SchemaBuilder{}
		required := []string{"identification_method"}
		b.Properties().Property("identification_method", validation.SchemaBuilder{}.Const(branch.Identification))

		requireString := func(key string) {
			required = append(required, key)
			b.Properties().Property(key, validation.SchemaBuilder{}.Type(validation.TypeString))
		}

		switch branch.Identification {
		case config.WorkflowIdentificationMethodEmail:
			requireString("login_id")
		case config.WorkflowIdentificationMethodPhone:
			requireString("login_id")
		case config.WorkflowIdentificationMethodUsername:
			requireString("login_id")
		default:
			// Skip the following code.
			continue
		}

		b.Required(required...)
		oneOf = append(oneOf, b)
	}

	b := validation.SchemaBuilder{}.
		Type(validation.TypeObject)

	if len(oneOf) > 0 {
		b.OneOf(oneOf...)
	}

	return b
}

func (i *InputSchemaSignupFlowStepIdentify) MakeInput(rawMessage json.RawMessage) (workflow.Input, error) {
	var input InputSignupFlowStepIdentify
	err := i.SchemaBuilder().ToSimpleSchema().Validator().ParseJSONRawMessage(rawMessage, &input)
	if err != nil {
		return nil, err
	}
	return &input, nil
}

type InputSignupFlowStepIdentify struct {
	IdentificationMethod config.WorkflowIdentificationMethod `json:"identification_method,omitempty"`

	LoginID string `json:"login,omitempty"`
}

var _ workflow.Input = &InputSignupFlowStepIdentify{}
var _ inputTakeIdentificationMethod = &InputSignupFlowStepIdentify{}
var _ inputTakeLoginID = &InputSignupFlowStepIdentify{}

func (*InputSignupFlowStepIdentify) Input() {}

func (i *InputSignupFlowStepIdentify) GetIdentificationMethod() config.WorkflowIdentificationMethod {
	return i.IdentificationMethod
}

func (i *InputSignupFlowStepIdentify) GetLoginID() string {
	return i.LoginID
}