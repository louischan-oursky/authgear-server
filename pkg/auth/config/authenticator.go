package config

var _ = Schema.Add("AuthenticatorConfig", `
{
	"type": "object",
	"properties": {
		"password": { "$ref": "#/$defs/AuthenticatorPasswordConfig" },
		"totp": { "$ref": "#/$defs/AuthenticatorTOTPConfig" },
		"oob_otp": { "$ref": "#/$defs/AuthenticatorOOBConfig" },
		"bearer_token": { "$ref": "#/$defs/AuthenticatorBearerTokenConfig" },
		"recovery_code": { "$ref": "#/$defs/AuthenticatorRecoveryCodeConfig" }
	}
}
`)

type AuthenticatorConfig struct {
	Password     *AuthenticatorPasswordConfig     `json:"password,omitempty"`
	TOTP         *AuthenticatorTOTPConfig         `json:"totp,omitempty"`
	OOB          *AuthenticatorOOBConfig          `json:"oob_otp,omitempty"`
	BearerToken  *AuthenticatorBearerTokenConfig  `json:"bearer_token,omitempty"`
	RecoveryCode *AuthenticatorRecoveryCodeConfig `json:"recovery_code,omitempty"`
}

var _ = Schema.Add("AuthenticatorPasswordConfig", `
{
	"type": "object",
	"properties": {
		"policy": { "$ref": "#/$defs/PasswordPolicyConfig" }
	}
}
`)

type AuthenticatorPasswordConfig struct {
	Policy *PasswordPolicyConfig `json:"policy,omitempty"`
}

var _ = Schema.Add("PasswordPolicyConfig", `
{
	"type": "object",
	"properties": {
		"min_length": { "type": "integer" },
		"uppercase_required": { "type": "boolean" },
		"lowercase_required": { "type": "boolean" },
		"digit_required": { "type": "boolean" },
		"symbol_required": { "type": "boolean" },
		"minimum_guessable_level": { "type": "integer" },
		"excluded_keywords": { "type": "array", "items": { "type": "string" } },
		"history_size": { "type": "integer" },
		"history_days": { "$ref": "#/$defs/DurationDays" }
	}
}
`)

type PasswordPolicyConfig struct {
	MinLength             int          `json:"min_length,omitempty"`
	UppercaseRequired     bool         `json:"uppercase_required,omitempty"`
	LowercaseRequired     bool         `json:"lowercase_required,omitempty"`
	DigitRequired         bool         `json:"digit_required,omitempty"`
	SymbolRequired        bool         `json:"symbol_required,omitempty"`
	MinimumGuessableLevel int          `json:"minimum_guessable_level,omitempty"`
	ExcludedKeywords      []string     `json:"excluded_keywords,omitempty"`
	HistorySize           int          `json:"history_size,omitempty"`
	HistoryDays           DurationDays `json:"history_days,omitempty"`
}

func (c *PasswordPolicyConfig) IsEnabled() bool {
	return c.HistorySize > 0 || c.HistoryDays > 0
}

var _ = Schema.Add("AuthenticatorTOTPConfig", `
{
	"type": "object",
	"properties": {
		"maximum": { "type": "integer" }
	}
}
`)

type AuthenticatorTOTPConfig struct {
	Maximum *int `json:"maximum,omitempty"`
}

func (c *AuthenticatorTOTPConfig) SetDefaults() {
	if c.Maximum == nil {
		c.Maximum = newInt(99)
	}
}

var _ = Schema.Add("AuthenticatorOOBConfig", `
{
	"type": "object",
	"properties": {
		"sms": { "$ref": "#/$defs/AuthenticatorOOBSMSConfig" },
		"email": { "$ref": "#/$defs/AuthenticatorOOBEmailConfig" }
	}
}
`)

type AuthenticatorOOBConfig struct {
	SMS   *AuthenticatorOOBSMSConfig   `json:"sms,omitempty"`
	Email *AuthenticatorOOBEmailConfig `json:"email,omitempty"`
}

var _ = Schema.Add("AuthenticatorOOBSMSConfig", `
{
	"type": "object",
	"properties": {
		"maximum": { "type": "integer" },
		"message": { "$ref": "#/$defs/SMSMessageConfig" }
	}
}
`)

type AuthenticatorOOBSMSConfig struct {
	Maximum *int             `json:"maximum,omitempty"`
	Message SMSMessageConfig `json:"message,omitempty"`
}

func (c *AuthenticatorOOBSMSConfig) SetDefaults() {
	if c.Maximum == nil {
		c.Maximum = newInt(99)
	}
}

var _ = Schema.Add("AuthenticatorOOBEmailConfig", `
{
	"type": "object",
	"properties": {
		"maximum": { "type": "integer" },
		"message": { "$ref": "#/$defs/EmailMessageConfig" }
	}
}
`)

type AuthenticatorOOBEmailConfig struct {
	Maximum *int               `json:"maximum,omitempty"`
	Message EmailMessageConfig `json:"message,omitempty"`
}

func (c *AuthenticatorOOBEmailConfig) SetDefaults() {
	if c.Maximum == nil {
		c.Maximum = newInt(99)
	}
	if c.Message["subject"] == "" {
		c.Message["subject"] = "Email Verification Instruction"
	}
}

var _ = Schema.Add("AuthenticatorBearerTokenConfig", `
{
	"type": "object",
	"properties": {
		"expire_in_days": { "$ref": "#/$defs/DurationDays" }
	}
}
`)

type AuthenticatorBearerTokenConfig struct {
	ExpireIn DurationDays `json:"expire_in_days,omitempty"`
}

func (c *AuthenticatorBearerTokenConfig) SetDefaults() {
	if c.ExpireIn == 0 {
		c.ExpireIn = DurationDays(30)
	}
}

var _ = Schema.Add("AuthenticatorRecoveryCodeConfig", `
{
	"type": "object",
	"properties": {
		"count": { "type": "integer" },
		"list_enabled": { "type": "integer" }
	}
}
`)

type AuthenticatorRecoveryCodeConfig struct {
	Count       int  `json:"count,omitempty"`
	ListEnabled bool `json:"list_enabled,omitempty"`
}

func (c *AuthenticatorRecoveryCodeConfig) SetDefaults() {
	if c.Count == 0 {
		c.Count = 16
	}
}
