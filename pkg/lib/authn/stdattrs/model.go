package stdattrs

import (
	"fmt"

	"github.com/authgear/authgear-server/pkg/util/nameutil"
)

type T map[string]interface{}

func (t T) FormattedName() string {
	// Choose between name or given_name+middle_name+family_name
	var name string
	if s, ok := t[Name].(string); ok && s != "" {
		name = s
	} else {
		givenName, _ := t[GivenName].(string)
		familyName, _ := t[FamilyName].(string)
		middleName, _ := t[MiddleName].(string)
		s := nameutil.Format(givenName, middleName, familyName)
		if s != "" {
			name = s
		}
	}

	nickname, _ := t[Nickname].(string)

	switch {
	case name == "" && nickname == "":
		return ""
	case name != "" && nickname == "":
		return name
	case name == "" && nickname != "":
		return nickname
	default:
		return fmt.Sprintf("%s (%s)", name, nickname)
	}
}

func (t T) ToClaims() map[string]interface{} {
	return map[string]interface{}(t)
}

// NonIdentityAware returns a copy of t with identity-aware attributes removed.
func (t T) NonIdentityAware() T {
	out := make(T)
	for k1, val := range t {
		for _, k2 := range NonIdentityAwareKeys {
			if k1 == k2 {
				out[k1] = val
			}
		}
	}
	return out
}

// MergedWith returns a T with that merged into t.
func (t T) MergedWith(that T) T {
	out := make(T)
	for k, v := range t {
		out[k] = v
	}
	for k, v := range that {
		out[k] = v
	}
	return out
}

const (
	// Sub is not used because we do not always use sub as the unique identifier for
	// an user from the identity provider.
	// Sub = "sub"
	Email               = "email"
	EmailVerified       = "email_verified"
	PhoneNumber         = "phone_number"
	PhoneNumberVerified = "phone_number_verified"
	PreferredUsername   = "preferred_username"
	FamilyName          = "family_name"
	GivenName           = "given_name"
	MiddleName          = "middle_name"
	Name                = "name"
	Nickname            = "nickname"
	Picture             = "picture"
	Profile             = "profile"
	Website             = "website"
	Gender              = "gender"
	Birthdate           = "birthdate"
	Zoneinfo            = "zoneinfo"
	Locale              = "locale"
	Address             = "address"
	Formatted           = "formatted"
	StreetAddress       = "street_address"
	Locality            = "locality"
	Region              = "region"
	PostalCode          = "postal_code"
	Country             = "country"
)

var NonIdentityAwareKeys []string = []string{
	FamilyName,
	GivenName,
	MiddleName,
	Name,
	Nickname,
	Picture,
	Profile,
	Website,
	Gender,
	Birthdate,
	Zoneinfo,
	Locale,
	Address,
}
