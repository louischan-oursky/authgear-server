package config

var _ = Schema.Add("HTTPConfig", `
{
	"type": "object",
	"properties": {
		"hosts": { "type": "array", "items": { "type": "string" } },
		"allowed_origins": { "type": "array", "items": { "type": "string" } }
	}
}
`)

type HTTPConfig struct {
	Hosts         []string `json:"hosts,omitempty"`
	AllowsOrigins []string `json:"allowed_origins,omitempty"`
}
