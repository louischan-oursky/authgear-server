- [Goals](#goals)
- [Non-goals](#non-goals)
- [Overview](#overview)
- [Review the authentication UI / UX of existing consumer apps](#review-the-authentication-ui--ux-of-existing-consumer-apps)
- [Review the design of various competitors](#review-the-design-of-various-competitors)
  * [Auth0](#auth0)
  * [Okta](#okta)
  * [Azure AD B2C](#azure-ad-b2c)
  * [Zitadel](#zitadel)
  * [Supertokens](#supertokens)
- [Design](#design)
  * [Design Principles](#design-principles)
  * [What is a signup flow](#what-is-a-signup-flow)
  * [What is a login flow](#what-is-a-login-flow)
  * [What is a reauth flow](#what-is-a-reauth-flow)
  * [What is account linking](#what-is-account-linking)
  * [Design of the configuration](#design-of-the-configuration)
    + [Design overview](#design-overview)
    + [SignupFlow](#signupflow)
    + [LoginFlow](#loginflow)
    + [SignupLoginFlow](#signuploginflow)
    + [ReauthFlow](#reauthflow)
    + [Use case example 1: Latte](#use-case-example-1-latte)
    + [Use case example 2: Uber](#use-case-example-2-uber)
    + [Use case example 3: Google](#use-case-example-3-google)
    + [Use case example 4: The Club](#use-case-example-4-the-club)
    + [Use case example 5: Manulife MPF](#use-case-example-5-manulife-mpf)
    + [Use case example 6: Comprehensive example](#use-case-example-6-comprehensive-example)
- [Appendix](#appendix)
  * [JSON schema](#json-schema)

## Goals

- Support customized signup flow
- Support customized login flow
- Support customized reauth flow
- Support more than 1 flows for signup / login / reauth
- Support combined signup and login flow
- The customized flows are supported by Default UI out of the box
- If Default UI does not suit the taste of the developer, the customized flows can be executed by a custom UI.
- (Future works) Support account linking

## Non-goals

- Build a generic workflow engine

## Overview

Before we get down to the design, we first

1. Review the authentication UI / UX of existing consumer apps
2. Review the design of various competitors

That will provide us insights into how to design our workflow

## Review the authentication UI / UX of existing consumer apps

This notion records the authentication flows of existing consumer apps in Hong Kong.
https://www.notion.so/oursky/Common-Signup-Login-Flows-f62e48724dc041d29aa0a77ec1dae806

Some important observations drawn from this review.
- Most consumer apps do not support 2FA.
- The authentication method is not necessarily tied to the identification method. For example, in The Club app, user can first enter their email address, and then receive a Phone OTP to sign in.

## Review the design of various competitors

### Auth0

Auth0 offers Triggers, Actions and Flows. https://auth0.com/docs/customize/actions/flows-and-triggers Auth0 does not support fully customized flows. Instead, it defines some Triggers, and allow the developer to write their own Actions to build Flows.

### Okta

Okta is based on Workflows. But the Workflows it offer are mainly for building business workflows, instead of customizing the authentication flow. In the documentation, it only documents how to customize a step in the authentication flow. https://help.okta.com/wf/en-us/Content/Topics/Workflows/connector-builder/authentication-custom.htm

### Azure AD B2C

Azure AD B2C allows customization via custom policy. Custom policy is configured by configuration files. The custom policy has a few key concepts.

- Claims are the foundation of a custom policy.
- User Journey defines how the user authenticates themselves.
- A User Journey contains several Orchestration Steps.
- Each Orchestration Step can be executed conditionally.
- An Orchestration Step must refer to a Technical profile.
- A Technical Profile defines its input Claims and output Claims.

Therefore, the end-user goes through the User Journey, with more and more Claims being collected in each Orchestration Step.

https://learn.microsoft.com/en-us/azure/active-directory-b2c/custom-policy-overview

### Zitadel

Zitadel is experimenting with a new Resource-based API. The Resource-based API has a Session API. The Session API is data-driven. For example, the developer can ask Zitadel to authenticate the user and verify the password by creating a session of the following shape

```json
{
  "checks": {
    "user": {
      "loginName": "mini@mouse.com"
    },
    "password": {
      "password": "V3ryS3cure!"
    }
  }
}
```

More complicated flows could be supported by supporting more `checks`, as proposed by [this comment](https://github.com/zitadel/zitadel/discussions/5875#discussioncomment-5985323)

https://github.com/zitadel/zitadel/discussions/5922

### Supertokens

Supertokens requires the developer to host a backend server to interactive with the Core Driver Interface (CDI) https://app.swaggerhub.com/apis/supertokens/CDI/2.21.1 The CDI is not very flexible. For example, it only supports some pre-defined recipe like EmailPassword Recipe, Passwordless Recipe.

## Design

### Design Principles

- We want to design a configuration such that the default UI can just read the configuration and execute the customized flows.
- We want to keep the guarantee that the existing configuration ensures every new user has some certain identities and authenticators.
- We want to be able to fulfill the authentication flows in existing consumer apps

### What is a signup flow
- Create 1 or more Identities. Later on, the User identify themselves with one of the Identities.
- Create 0 or more Authenticators. The User authenticates themselves with one of the Authenticators if needed.
- (Optional) Collect user profile (i.e. standard attributes and custom attributes)

### What is a login flow
- Identify the User with an Identity
- Depending on the Identity, authenticator the User with the Authenticators. Note that the pre-selected Authenticator is usually associated with the Identity.
- (Optional) Further authenticate the User with **other** Authenticators.

Suppose the User has a Email Login ID Identity `johndoe@gmail.com`, a Email OOB-OTP Authenticator `johndoe@gmail.com`, a Phone Login ID Identity `+85298765432`, a Phone OOB-OTP Authenticator `+85298765432`, a Password Authenticator, and a OAuth Identity `johndoe@gmail.com`.

If the User identifies themselves with the Email Login ID Identity `johndoe@gmail.com`, then the User can authenticate themselves with:
1. Email OOB-OTP Authenticator `johndoe@gmail.com`
2. Password Authenticator
3. Phone OOB-OTP Authenticator `+85298765432`. Note that this Authenticator is NOT associated with the identifying Identity, but it can also be used to authenticate the User.

If the User identifies themselves with the OAuth Identity `johndoe@gmail.com`, then the User DOES NOT need to authenticate themselves. This is how most other applications work.

### What is a reauth flow
- Authenticate the User with any Authenticators.

### What is account linking

Account linking happens in a login flow.
Each login flow can optionally specify the conditions when account linking can occur.
If no conditions are specified or no conditions are matched, an error is returned, telling the end-user to sign in with the existing identity instead.

The login flow is then proceeded as if the existing identity were selected.

At the end of the flow, the new identity is added to the account.

### Design of the configuration

#### Design overview

- A flow has one or more `steps`.
- A step MAY optionally have an `id`.
- A step must have a `type`.
- A `type` step is specific to the kind of the flow. For example, only SignupFlow has the `type: user_profile` step.
- Some steps allow branching. Those steps have `one_of`.
- The branch of a step MAY optionally have zero or more `steps`.

#### SignupFlow

Example:

```yaml
signup_flows:
- id: default_signup_flow
  steps:
  - id: setup_identity
    type: identify
    one_of:
    - identification: phone
      steps:
      - type: authenticate
        one_of:
        - authentication: primary_oob_otp_sms
          target_step: setup_identity
      - type: verify
        target_step: setup_identity
    - identification: email
      steps:
      - type: authenticate
        one_of:
        - authentication: primary_oob_otp_email
          target_step: setup_identity
      - type: verify
        target_step: setup_identity
  - type: authenticate
    one_of:
    - authentication: primary_password
  - id: setup_phone_2fa
    type: authenticate
    one_of:
    - authentication: secondary_oob_otp_sms
  - type: verify
    target_step: setup_phone_2fa
  - type: user_profile
    user_profile:
    - pointer: /given_name
      required: true
    - pointer: /family_name
      required: true
  # Collect custom attributes.
  - type: user_profile
    user_profile:
    - pointer: /x_age
      required: true
```

#### LoginFlow

```yaml
login_flows:
# Sign in with a phone number and OTP via SMS to any phone number the account has.
- id: phone_otp_to_any_phone
  steps:
  - type: identify
    one_of:
    - identification: phone
  - type: authenticate
    one_Of:
    - authentication: primary_oob_otp_sms

# Sign in with a phone number and OTP via SMS to the same phone number.
- id: phone_otp_to_same_phone
  steps:
  - id: identify
    type: identify
    one_of:
    - identification: phone
  - type: authenticate
    one_of:
    - authentication: primary_oob_otp_sms
      target_step: identify

# Sign in with a phone number and a password
- id: phone_password
  steps:
  - type: identify
    one_of:
    - identification: phone
  - type: authenticate
    one_of:
    - authentication: primary_password

# Sign in with a phone number, or an email address, with a password
- id: phone_email_password
  steps:
  - type: identify
    one_of:
    - identification: phone
    - identification: email
  - type: authenticate
    one_of:
    - authentication: primary_password

# Sign in with an email address, a password and a TOTP
- id: email_password_totp
  steps:
  - type: identify
    one_of:
    - identification: email
  - type: authenticate
    one_of:
    - authentication: primary_password
  - type: authenticate
    one_of:
    - authentication: secondary_totp

# Sign in with an email address, a password. Perform 2FA if the end-user has configured.
- id: email_password_optional_2fa
  steps:
  - type: identify
    one_of:
    - identification: email
  - type: authenticate
    one_of:
    - authentication: primary_password
  - type: authenticate
    # If the end-user has no applicable authentication method,
    # then this step is optional.
    # optional by default is false, meaning that the step is required.
    optional: true
    one_of:
    - authentication: secondary_totp

- id: account_linking
  account_linking:
    conditions:
    # The standard_attribute to determine whether two identities are the "same".
    # Account linking happens when the existing identity is Email Login ID,
    # and the incoming identity is any OAuth identity.
    - standard_attribute: /email
      existing:
        identification: email
      incoming:
        identification: oauth
    # Account linking happens when the existing identity is any OAuth identity,
    # and the incoming identity is Email Login ID.
    - standard_attribute: /email
      existing:
        identification: oauth
      incoming:
        identification: email
  steps:
  - type: identify
    one_of:
    - identification: oauth
    - identification: email
      steps:
      - type: authenticate
        one_of:
        - authentication: primary_password
```

#### SignupLoginFlow

Example:

```yaml
signup_login_flows:
- id: default_signup_login_flow
  steps:
  - type: identify
    one_of:
    - identification: phone
      signup_flow: default_signup_flow
      login_flow: default_login_flow
    - identification: email
      signup_flow: default_signup_flow
      login_flow: default_login_flow
```

#### ReauthFlow

Example:

```yaml
reauth_flows:
# Re-authenticate with primary password.
- id: reauth_password
  steps:
  - type: authenticate
    one_of:
    - authentication: primary_password

# Re-authenticate with any 2nd factor, assuming that 2FA is required in signup flow.
- id: reauth_2fa
  steps:
  - type: authenticate
    one_of:
    - authentication: secondary_totp
    - authentication: secondary_sms_code

# Re-authenticate with the 1st factor AND the 2nd factor.
- id: reauth_full
  steps:
  - type: authenticate
    one_of:
    - authentication: primary_password
  - type: authenticate
    one_of:
    - authentication: secondary_totp
    - authentication: secondary_sms_code
```

#### Use case example 1: Latte

```yaml
signup_flows:
- id: default_signup_flow
  steps:
  - id: setup_phone
    type: identify
    one_of:
    - identification: phone
  - type: authenticate
    one_of:
    - authentication: primary_oob_otp_sms
      target_step: setup_phone
  - type: verify
    target_step: setup_phone
  - id: setup_email
    type: identify
    one_of:
    - identification: email
  - type: authenticate
    one_of:
    - authentication: primary_oob_otp_email
      target_step: setup_email
  - type: authenticate
    one_of:
    - authentication: primary_password

login_flows:
- id: default_login_flow
  steps:
  - type: identify
    one_of:
    - identification: phone
  - type: authenticate
    one_of:
    - authentication: primary_oob_otp_sms
  - type: authenticate
    one_of:
    - authentication: primary_oob_otp_email
    - authentication: primary_password
```

#### Use case example 2: Uber

```yaml
signup_flows:
- id: default_signup_flow
  steps:
  - id: setup_first_identity
    type: identify
    one_of:
    - identification: phone
      steps:
      - type: authenticate
        one_of:
        - authentication: primary_oob_otp_sms
          target_step: setup_first_identity
      - type: verify
        target_step: setup_first_identity
      - id: setup_second_identity
        type: identify
        one_of:
        - identification: email
      - type: authenticate
        one_of:
        - authentication: primary_oob_otp_email
          target_step: setup_second_identity
      - type: verify
        target_step: setup_second_identity
    - identification: email
      - type: authenticate
        one_of:
        - authentication: primary_oob_otp_email
          target_step: setup_first_identity
      - type: verify
        target_step: setup_first_identity
      - id: setup_second_identity
        type: identify
        one_of:
        - identification: phone
      - type: authenticate
        one_of:
        - authentication: primary_oob_otp_sms
          target_step: setup_second_identity
      - type: verify
        target_step: setup_second_identity
  - type: authenticate
    one_of:
    - authentication: primary_password

login_flows:
- id: default_login_flow
  steps:
  - type: identify
    one_of:
    - identification: phone
      steps:
      - type: authenticate
        one_of:
        - authentication: primary_oob_otp_sms
        - authentication: primary_password
    - identification: email
      steps:
      - type: authenticate
        one_of:
        - authentication: primary_oob_otp_email
        - authentication: primary_oob_otp_sms
        - authentication: primary_password

signup_login_flows:
- id: default_signup_login_flow
  steps:
  - type: identify
    one_of:
    - identification: phone
      login_flow: default_login_flow
      signup_flow: default_signup_flow
    - identification: email
      login_flow: default_login_flow
      signup_flow: default_signup_flow
```

#### Use case example 3: Google

```yaml
signup_flows:
- id: default_signup_flow
  steps:
  - type: identify
    one_of:
    - identification: email
  - type: authenticate
    one_of:
    - authentication: primary_password

login_flows:
- id: default_login_flow
  steps:
  - type: identify
    one_of:
    - identification: email
  - type: authenticate
    one_of:
    - authentication: primary_password
  - type: authenticate
    one_of:
    - authentication: secondary_totp
    - authentication: secondary_oob_otp_sms
```

#### Use case example 4: The Club

```yaml
# signup_flows is omitted here because the exact signup flow is unknown.

login_flows:
- id: default_login_flow
  steps:
  - type: identify
    one_of:
    - identification: email
    - identification: phone
    - identification: username
  - type: authenticate
    one_of:
    - authentication: primary_password
    - authentication: primary_oob_otp_sms
```

#### Use case example 5: Manulife MPF

```yaml
# signup_flows are omitted because it does not have public signup.

login_flows:
- id: default_login_flow
  steps:
  - type: identify
    one_of:
    - identification: username
  - type: authenticate
    one_of:
    - authentication: primary_password
  - type: authenticate
    one_of:
    - authentication: primary_oob_otp_sms
    - authentication: primary_oob_otp_email
```

#### Use case example 6: Comprehensive example

```yaml
signup_flows:
# The end user sign up with OAuth without password or 2FA.
# Or the end user sign up with verified email with password and 2FA.
- id: default_signup_flow
  steps:
  - id: setup_identity
    type: identify
    one_of:
    - identification: oauth
    - identification: email
      steps:
      - type: authenticate
        one_of:
        - authentication: primary_oob_otp_email
          target_step: setup_identity
      - type: verify
        target_step: setup_identity
      - type: authenticate
        one_of:
        - authentication: primary_password
      - type: authenticate
        one_of:
        - authentication: secondary_totp

login_flows:
# The end user can sign in with OAuth.
# The end user can sign in with passkey directly.
# The end user can sign in with email with OTP, password, or passkey, and with 2FA.
- id: default_login_flow
  steps:
  - type: identify
    one_of:
    - identification: oauth
    - identification: passkey
    - identification: email
      steps:
      - type: authenticate
        one_of:
        - authentication: primary_passkey
        - authentication: primary_password
          steps:
          - type: authenticate
            one_of:
            - authentication: secondary_totp
        - authentication: primary_oob_otp_email
          steps:
          - type: authenticate
            one_of:
            - authentication: secondary_totp
```

## Appendix

### JSON schema

```
{
  "$defs": {
    "WorkflowSignupFlowConfig": {
      "type": "object",
      "required": ["id", "steps"],
      "properties": {
        "id": { "type": "string" },
        "steps": {
          "type": "array",
          "items": { "$ref": "#/$defs/WorkflowSignupFlowStep" }
        }
      }
    },
    "WorkflowSignupFlowStep": {
      "type": "object",
      "required": ["type"],
      "properties": {
        "id": { "type": "string" },
        "type": {
          "type": "string",
          "enum": [
            "identify",
            "authenticate",
            "verify",
            "user_profile"
          ]
        }
      },
      "allOf": [
        {
          "if": {
            "required": ["type"],
            "properties": {
              "type": { "const": "identify" }
            }
          },
          "then": {
            "required": ["one_of"],
            "properties": {
              "one_of": {
                "type": "array",
                "items": { "$ref": "#/$defs/WorkflowSignupFlowIdentify" }
              }
            }
          }
        },
        {
          "if": {
            "required": ["type"],
            "properties": {
              "type": { "const": "authenticate" }
            }
          },
          "then": {
            "required": ["one_of"],
            "properties": {
              "one_of": {
                "type": "array",
                "items": { "$ref": "#/$defs/WorkflowSignupFlowAuthenticate" }
              }
            }
          }
        },
        {
          "if": {
            "required": ["type"],
            "properties": {
              "type": { "const": "verify" }
            }
          },
          "then": {
            "required": ["target_step"],
            "properties": {
              "target_step": { "type": "string" }
            }
          }
        },
        {
          "if": {
            "required": ["type"],
            "properties": {
              "type": { "const": "user_profile" }
            }
          },
          "then": {
            "required": ["user_profile"],
            "properties": {
              "user_profile": {
                "type": "array",
                "items": { "$ref": "#/$defs/WorkflowSignupFlowUserProfile" }
              }
            }
          }
        }
      ]
    },
    "WorkflowSignupFlowIdentify": {
      "type": "object",
      "required": ["identification"],
      "properties": {
        "identification": { "$ref": "#/$defs/WorkflowIdentificationMethod" },
        "steps": {
          "type": "array",
          "items": { "$ref": "#/$defs/WorkflowSignupFlowStep" }
        }
      }
    },
    "WorkflowSignupFlowAuthenticate": {
      "type": "object",
      "required": ["authentication"],
      "properties": {
        "authentication": { "$ref": "#/$defs/WorkflowAuthenticationMethod" },
        "target_step": { "type": "string" },
        "steps": {
          "type": "array",
          "items": { "$ref": "#/$defs/WorkflowSignupFlowStep" }
        }
      }
    },
    "WorkflowSignupFlowUserProfile": {
      "type": "object",
      "required": ["pointer", "required"],
      "properties": {
        "pointer": { "type": "string" },
        "required": { "type": "boolean" }
      }
    },
    "WorkflowLoginFlowConfig": {
      "type": "object",
      "required": ["id", "steps"],
      "properties": {
        "id": { "type": "string" },
        "steps": {
          "type": "array",
          "items": { "$ref": "#/$defs/WorkflowLoginFlowStep" }
        },
        "account_linking": { "$ref": "#/$defs/WorkflowLoginFlowAccountLinking" }
      }
    },
    "WorkflowLoginFlowAccountLinking": {
      "type": "object",
      "required": ["conditions"],
      "properties": {
        "conditions": {
          "type": "array",
          "items": { "$ref": "#/$defs/WorkflowLoginFlowAccountLinkingCondition" }
        }
      }
    },
    "WorkflowLoginFlowAccountLinkingCondition": {
      "type": "object",
      "required": ["standard_attribute", "existing", "incoming"],
      "properties": {
        "standard_attribute": {
          "type": "string",
          "enum": [
            "/email"
          ]
        },
        "existing": {
          "type": "object",
          "properties": {
            "identification": {
              "type": "string",
              "enum": [
                "email",
                "oauth"
              ]
            }
          }
        },
        "incoming": {
          "type": "object",
          "properties": {
            "identification": {
              "type": "string",
              "enum": [
                "email",
                "oauth"
              ]
            }
          }
        }
      }
    },
    "WorkflowLoginFlowStep": {
      "type": "object",
      "required": ["type"],
      "properties": {
        "id": { "type": "string" },
        "type": {
          "type": "string",
          "enum": [
            "identify",
            "authenticate"
          ]
        }
      },
      "allOf": [
        {
          "if": {
            "required": ["type"],
            "properties": {
              "type": { "const": "identify" }
            }
          },
          "then": {
            "required": ["one_of"],
            "properties": {
              "one_of": {
                "type": "array",
                "items": { "$ref": "#/$defs/WorkflowLoginFlowIdentify" }
              }
            }
          }
        },
        {
          "if": {
            "required": ["type"],
            "properties": {
              "type": { "const": "authenticate" }
            }
          },
          "then": {
            "required": ["one_of"],
            "properties": {
              "optional": { "type": "boolean" },
              "one_of": {
                "type": "array",
                "items": { "$ref": "#/$defs/WorkflowLoginFlowAuthenticate" }
              }
            }
          }
        }
      ]
    },
    "WorkflowLoginFlowIdentify": {
      "type": "object",
      "required": ["identification"],
      "properties": {
        "identification": { "$ref": "#/$defs/WorkflowIdentificationMethod" },
        "steps": {
          "type": "array",
          "items": { "$def": "#/$defs/WorkflowLoginFlowStep" }
        }
      }
    },
    "WorkflowLoginFlowAuthenticate": {
      "type": "object",
      "required": ["authentication"],
      "properties": {
        "authentication": { "$ref": "#/$defs/WorkflowAuthenticationMethod" },
        "target_step": { "type": "string" },
        "steps": {
          "type": "array",
          "items": { "$ref": "#/$defs/WorkflowLoginFlowStep" }
        }
      }
    },
    "WorkflowSignupLoginFlowConfig": {
      "type": "object",
      "required": ["id", "steps"],
      "properties": {
        "id": { "type": "string" },
        "steps": {
          "type": "array",
          "items": { "$ref": "#/$defs/WorkflowSignupLoginFlowStep" }
        }
      }
    },
    "WorkflowSignupLoginFlowStep": {
      "type": "object",
      "required": ["type"],
      "properties": {
        "id": { "type": "string" },
        "type": {
          "type": "string",
          "enum": [
            "identify"
          ]
        }
      },
      "allOf": [
        {
          "if": {
            "required": ["type"],
            "properties": {
              "type": { "const": "identify" }
            }
          },
          "then": {
            "required": ["one_of"],
            "properties": {
              "one_of": {
                "type": "array",
                "items": { "$ref": "#/$defs/WorkflowSignupLoginFlowIdentify" }
              }
            }
          }
        }
      ]
    },
    "WorkflowSignupLoginFlowIdentify": {
      "type": "object",
      "required": ["identification", "signup_flow", "login_flow"],
      "properties": {
        "identification": { "$ref": "#/$defs/WorkflowIdentificationMethod" },
        "signup_flow": { "type": "string" },
        "login_flow": { "type": "string" }
      }
    },
    "WorkflowReauthFlowConfig": {
      "type": "object",
      "required": ["id", "steps"],
      "properties": {
        "id": { "type": "string" },
        "steps": {
          "type": "array",
          "items": { "$ref": "#/$defs/WorkflowReauthFlowStep" }
        }
      }
    },
    "WorkflowReauthFlowStep": {
      "type": "object",
      "required": ["type"],
      "properties": {
        "id": { "type": "string" },
        "type": {
          "type": "string",
          "enum": [
            "authenticate"
          ]
        }
      },
      "allOf": [
        {
          "if": {
            "required": ["type"],
            "properties": {
              "type": { "const": "authenticate" }
            }
          },
          "then": {
            "required": ["one_of"],
            "properties": {
              "optional": { "type": "boolean" },
              "one_of": {
                "type": "array",
                "items": { "$ref": "#/$defs/WorkflowReauthFlowAuthenticate" }
              }
            }
          }
        }
      ]
    },
    "WorkflowReauthFlowAuthenticate": {
      "type": "object",
      "required": ["authentication"],
      "properties": {
        "authentication": { "$ref": "#/$defs/WorkflowAuthenticationMethod" },
        "target_step": { "type": "string" },
        "steps": {
          "type": "array",
          "items": { "$ref": "#/$defs/WorkflowReauthFlowStep" }
        }
      }
    },
    "WorkflowIdentificationMethod": {
      "type": "string",
      "enum": [
        "email",
        "phone",
        "username",
        "oauth",
        "passkey",
        "siwe"
      ]
    },
    "WorkflowAuthenticationMethod": {
      "type": "string",
      "enum": [
        "primary_password",
        "primary_passkey",
        "primary_oob_otp_email",
        "primary_oob_otp_sms",
        "secondary_password",
        "secondary_totp",
        "secondary_oob_otp_email",
        "secondary_oob_otp_sms"
      ]
    }
  },
  "properties": {
    "signup_flows": {
      "type": "array",
      "items": { "$ref": "#/$defs/WorkflowSignupFlowConfig" }
    },
    "login_flows": {
      "type": "array",
      "items": { "$ref": "#/$defs/WorkflowLoginFlowConfig" }
    },
    "signup_login_flows": {
      "type": "array",
      "items": { "$ref": "#/$defs/WorkflowSignupLoginFlowConfig" }
    },
    "reauth_flows": {
      "type": "array",
      "items": { "$ref": "#/$defs/WorkflowReauthFlowConfig" }
    }
  }
}
```