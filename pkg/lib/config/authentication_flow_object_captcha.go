package config

var _ = Schema.Add("AuthenticationFlowObjectCaptchaConfig", `
{
	"type": "object",
	"additionalProperties": false,
	"properties": {
		"enabled": { "type": "boolean" }
	}
}
`)

type AuthenticationFlowObjectCaptchaConfig struct {
	Enabled *bool `json:"enabled,omitempty"`
}

var _ = Schema.Add("AuthenticationFlowCaptcha", `
{
	"type": "object",
	"additionalProperties": false,
	"properties": {
		"required": { "type": "boolean" }
	}
}
`)

type AuthenticationFlowCaptcha struct {
	Required *bool `json:"required,omitempty"`
}