package workflow2

import (
	"fmt"
	"reflect"
)

// Flow is a instantiable intent by the public.
type Flow interface {
	Intent
	FlowType() FlowType
	FlowInit(r FlowReference)
}

// FlowType denotes the type of the intents.
type FlowType string

const (
	FlowTypeSignup FlowType = "signup_flow"
	FlowTypeLogin  FlowType = "login_flow"
)

// FlowReference is an API object.
type FlowReference struct {
	Type FlowType `json:"type"`
	ID   string   `json:"id"`
}

type flowFactory func() Flow

var flowRegistry = map[FlowType]flowFactory{}

// RegisterFlow is for registering a flow.
func RegisterFlow(flow Flow) {
	flowGoType := reflect.TypeOf(flow).Elem()

	flowType := flow.FlowType()
	factory := flowFactory(func() Flow {
		return reflect.New(flowGoType).Interface().(Flow)
	})

	if _, registered := flowRegistry[flowType]; registered {
		panic(fmt.Errorf("workflow: duplicated flow type: %v", flowType))
	}

	flowRegistry[flowType] = factory

	RegisterIntent(flow)
}

// InstantiateFlow is used by the HTTP layer to instantiate a Flow.
func InstantiateFlow(f FlowReference) (Flow, error) {
	factory, ok := flowRegistry[f.Type]
	if !ok {
		return nil, ErrUnknownFlow
	}

	flow := factory()
	flow.FlowInit(f)
	return flow, nil
}