package config

import (
	"github.com/authgear/authgear-server/pkg/api/model"
)

var _ = Schema.Add("AuthenticationConfig", `
{
	"type": "object",
	"additionalProperties": false,
	"properties": {
		"public_signup_disabled": {
			"type": "boolean"
		},
		"identities": {
			"type": "array",
			"items": { "$ref": "#/$defs/IdentityType" },
			"uniqueItems": true
		},
		"primary_authenticators": {
			"type": "array",
			"items": { "$ref": "#/$defs/PrimaryAuthenticatorType" },
			"uniqueItems": true
		},
		"secondary_authenticators": {
			"type": "array",
			"items": { "$ref": "#/$defs/SecondaryAuthenticatorType" },
			"uniqueItems": true
		},
		"secondary_authentication_mode": { "$ref": "#/$defs/SecondaryAuthenticationMode" },
		"device_token": { "$ref": "#/$defs/DeviceTokenConfig" },
		"recovery_code": { "$ref": "#/$defs/RecoveryCodeConfig" }
	}
}
`)

var _ = Schema.Add("IdentityType", `
{
	"type": "string",
	"enum": ["login_id", "oauth", "anonymous", "biometric", "passkey"]
}
`)

var _ = Schema.Add("PrimaryAuthenticatorType", `
{
	"type": "string",
	"enum": ["password", "passkey", "oob_otp_email", "oob_otp_sms"]
}
`)

var _ = Schema.Add("SecondaryAuthenticatorType", `
{
	"type": "string",
	"enum": ["password", "oob_otp_email", "oob_otp_sms", "totp"]
}
`)

type AuthenticationConfig struct {
	Identities                  []model.IdentityType        `json:"identities,omitempty"`
	PrimaryAuthenticators       *[]model.AuthenticatorType  `json:"primary_authenticators,omitempty"`
	SecondaryAuthenticators     *[]model.AuthenticatorType  `json:"secondary_authenticators,omitempty"`
	SecondaryAuthenticationMode SecondaryAuthenticationMode `json:"secondary_authentication_mode,omitempty"`
	DeviceToken                 *DeviceTokenConfig          `json:"device_token,omitempty"`
	RecoveryCode                *RecoveryCodeConfig         `json:"recovery_code,omitempty"`
	PublicSignupDisabled        bool                        `json:"public_signup_disabled,omitempty"`
}

func (c *AuthenticationConfig) SetDefaults() {
	if c.Identities == nil {
		c.Identities = []model.IdentityType{
			model.IdentityTypeOAuth,
			model.IdentityTypeLoginID,
			model.IdentityTypePasskey,
		}
	}
	if c.PrimaryAuthenticators == nil {
		c.PrimaryAuthenticators = &[]model.AuthenticatorType{
			model.AuthenticatorTypePassword,
			model.AuthenticatorTypePasskey,
		}
	}
	if c.SecondaryAuthenticators == nil {
		c.SecondaryAuthenticators = &[]model.AuthenticatorType{
			model.AuthenticatorTypeTOTP,
		}
	}
	if c.SecondaryAuthenticationMode == SecondaryAuthenticationModeDefault {
		c.SecondaryAuthenticationMode = SecondaryAuthenticationModeIfExists
	}
}

var _ = Schema.Add("SecondaryAuthenticationMode", `
{
	"type": "string",
	"enum": ["disabled", "if_exists", "required"]
}
`)

type SecondaryAuthenticationMode string

const (
	SecondaryAuthenticationModeDefault  SecondaryAuthenticationMode = ""
	SecondaryAuthenticationModeDisabled SecondaryAuthenticationMode = "disabled"
	SecondaryAuthenticationModeIfExists SecondaryAuthenticationMode = "if_exists"
	SecondaryAuthenticationModeRequired SecondaryAuthenticationMode = "required"
)

func (m SecondaryAuthenticationMode) IsDisabled() bool {
	return m == SecondaryAuthenticationModeDisabled
}

var _ = Schema.Add("DeviceTokenConfig", `
{
	"type": "object",
	"additionalProperties": false,
	"properties": {
		"disabled": { "type": "boolean" },
		"expire_in_days": { "$ref": "#/$defs/DurationDays" }
	}
}
`)

type DeviceTokenConfig struct {
	Disabled bool         `json:"disabled,omitempty"`
	ExpireIn DurationDays `json:"expire_in_days,omitempty"`
}

func (c *DeviceTokenConfig) SetDefaults() {
	if c.ExpireIn == 0 {
		c.ExpireIn = DurationDays(30)
	}
}

var _ = Schema.Add("RecoveryCodeConfig", `
{
	"type": "object",
	"additionalProperties": false,
	"properties": {
		"disabled": { "type": "boolean" },
		"count": { "type": "integer", "minimum": 10, "maximum": 50 },
		"list_enabled": { "type": "boolean" }
	}
}
`)

type RecoveryCodeConfig struct {
	Disabled    *bool `json:"disabled,omitempty"`
	Count       int   `json:"count,omitempty"`
	ListEnabled bool  `json:"list_enabled,omitempty"`
}

func (c *RecoveryCodeConfig) SetDefaults() {
	if c.Disabled == nil {
		c.Disabled = newBool(false)
	}
	if c.Count == 0 {
		c.Count = 16
	}
}
