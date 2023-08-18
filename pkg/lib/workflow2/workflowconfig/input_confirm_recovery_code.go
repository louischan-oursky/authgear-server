package workflowconfig

import (
	"encoding/json"

	workflow "github.com/authgear/authgear-server/pkg/lib/workflow2"
	"github.com/authgear/authgear-server/pkg/util/validation"
)

var InputConfirmRecoveryCodeSchemaBuilder validation.SchemaBuilder

func init() {
	InputConfirmRecoveryCodeSchemaBuilder = validation.SchemaBuilder{}.
		Type(validation.TypeObject).
		Required("confirm_recovery_code")

	InputConfirmRecoveryCodeSchemaBuilder.Properties().Property(
		"confirm_recovery_code",
		validation.SchemaBuilder{}.
			Type(validation.TypeBoolean).
			Const(true),
	)
}

type InputConfirmRecoveryCode struct{}

var _ workflow.InputSchema = &InputConfirmRecoveryCode{}
var _ workflow.Input = &InputConfirmRecoveryCode{}
var _ inputConfirmRecoveryCode = &InputConfirmRecoveryCode{}

func (*InputConfirmRecoveryCode) SchemaBuilder() validation.SchemaBuilder {
	return InputConfirmRecoveryCodeSchemaBuilder
}

func (i *InputConfirmRecoveryCode) MakeInput(rawMessage json.RawMessage) (workflow.Input, error) {
	var input InputConfirmRecoveryCode
	err := i.SchemaBuilder().ToSimpleSchema().Validator().ParseJSONRawMessage(rawMessage, &input)
	if err != nil {
		return nil, err
	}
	return &input, nil
}

func (*InputConfirmRecoveryCode) Input() {}

func (*InputConfirmRecoveryCode) ConfirmRecoveryCode() {}
