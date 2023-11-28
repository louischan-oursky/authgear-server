package stdattrs

import (
	"fmt"
	"sort"
	"time"

	"github.com/authgear/authgear-server/pkg/api/model"
	"github.com/authgear/authgear-server/pkg/lib/authn/identity"
	"github.com/authgear/authgear-server/pkg/lib/authn/stdattrs"
	"github.com/authgear/authgear-server/pkg/lib/authn/user"
	"github.com/authgear/authgear-server/pkg/lib/config"
	"github.com/authgear/authgear-server/pkg/lib/feature/verification"
	"github.com/authgear/authgear-server/pkg/util/accesscontrol"
	"github.com/authgear/authgear-server/pkg/util/slice"
)

type ClaimStore interface {
	ListByClaimName(userID string, claimName string) ([]*verification.Claim, error)
	ListByUserIDsAndClaimNames(userIDs []string, claimNames []string) ([]*verification.Claim, error)
}

type ServiceNoEvent struct {
	UserProfileConfig *config.UserProfileConfig
	Identities        IdentityService
	UserQueries       UserQueries
	UserStore         UserStore
	ClaimStore        ClaimStore
	Transformer       Transformer
}

func (s *ServiceNoEvent) PopulateIdentityAwareStandardAttributes0(originalStdAttrs map[string]interface{}, unsortedIdentities []*identity.Info) (map[string]interface{}, bool) {
	stdAttrs := stdattrs.T(originalStdAttrs).Clone().ToClaims()

	sortedIdentities := make([]*identity.Info, len(unsortedIdentities))
	copy(sortedIdentities, unsortedIdentities)

	// Sort the identities with newer ones ordered first.
	sort.SliceStable(sortedIdentities, func(i, j int) bool {
		a := sortedIdentities[i]
		b := sortedIdentities[j]
		return a.CreatedAt.After(b.CreatedAt)
	})

	// Generate a list of emails, phone numbers and usernames belong to the user.
	var emails []string
	var phoneNumbers []string
	var preferredUsernames []string
	for _, iden := range sortedIdentities {
		standardClaims := iden.IdentityAwareStandardClaims()
		if email, ok := standardClaims[model.ClaimEmail]; ok && email != "" {
			emails = append(emails, email)
		}
		if phoneNumber, ok := standardClaims[model.ClaimPhoneNumber]; ok && phoneNumber != "" {
			phoneNumbers = append(phoneNumbers, phoneNumber)
		}
		if preferredUsername, ok := standardClaims[model.ClaimPreferredUsername]; ok && preferredUsername != "" {
			preferredUsernames = append(preferredUsernames, preferredUsername)
		}
	}

	updated := false

	// Clear dangling standard attributes.
	clear := func(key string, allowedValues []string) {
		if value, ok := stdAttrs[key].(string); ok {
			if !slice.ContainsString(allowedValues, value) {
				delete(stdAttrs, key)
				updated = true
			}
		}
	}
	clear(stdattrs.Email, emails)
	clear(stdattrs.PhoneNumber, phoneNumbers)
	clear(stdattrs.PreferredUsername, preferredUsernames)

	// Populate standard attributes.
	populate := func(key string, allowedValues []string) {
		if _, ok := stdAttrs[key].(string); !ok {
			if len(allowedValues) > 0 {
				stdAttrs[key] = allowedValues[0]
				updated = true
			}
		}
	}
	populate(stdattrs.Email, emails)
	populate(stdattrs.PhoneNumber, phoneNumbers)
	populate(stdattrs.PreferredUsername, preferredUsernames)

	return stdAttrs, updated
}

func (s *ServiceNoEvent) PopulateIdentityAwareStandardAttributes(userID string) (err error) {
	// Get all the identities this user has.
	identities, err := s.Identities.ListByUser(userID)
	if err != nil {
		return
	}

	user, err := s.UserQueries.GetRaw(userID)
	if err != nil {
		return
	}

	stdAttrs, updated := s.PopulateIdentityAwareStandardAttributes0(user.StandardAttributes, identities)
	if updated {
		err = s.UserStore.UpdateStandardAttributes(userID, stdAttrs)
		if err != nil {
			return
		}
	}

	return
}

func (s *ServiceNoEvent) UpdateStandardAttributes0(role accesscontrol.Role, u *user.User, identities []*identity.Info, stdAttrsToUpdate map[string]interface{}) (map[string]interface{}, error) {
	// Remove derived attributes to avoid failing the validation.
	stdAttrs := stdattrs.T(stdAttrsToUpdate).WithDerivedAttributesRemoved()

	// Transform if needed.
	for key, value := range stdAttrs {
		value, err := s.Transformer.RepresentationFormToStorageForm(key, value)
		if err != nil {
			return nil, err
		}
		stdAttrs[key] = value
	}

	err := stdattrs.Validate(stdattrs.T(stdAttrs))
	if err != nil {
		return nil, err
	}

	accessControl := s.UserProfileConfig.StandardAttributes.GetAccessControl()
	err = stdattrs.T(u.StandardAttributes).CheckWrite(
		accessControl,
		role,
		stdattrs.T(stdAttrs),
	)
	if err != nil {
		return nil, err
	}

	ownedEmails := make(map[string]struct{})
	ownedPhoneNumbers := make(map[string]struct{})
	ownedPreferredUsernames := make(map[string]struct{})
	for _, iden := range identities {
		standardClaims := iden.IdentityAwareStandardClaims()
		if email, ok := standardClaims[model.ClaimEmail]; ok && email != "" {
			ownedEmails[email] = struct{}{}
		}
		if phoneNumber, ok := standardClaims[model.ClaimPhoneNumber]; ok && phoneNumber != "" {
			ownedPhoneNumbers[phoneNumber] = struct{}{}
		}
		if preferredUsername, ok := standardClaims[model.ClaimPreferredUsername]; ok && preferredUsername != "" {
			ownedPreferredUsernames[preferredUsername] = struct{}{}
		}
	}

	check := func(key string, allowedValues map[string]struct{}) error {
		if value, ok := stdAttrs[key].(string); ok {
			_, allowed := allowedValues[value]
			if !allowed {
				return fmt.Errorf("unowned %v: %v", key, value)
			}
		}
		return nil
	}

	err = check(stdattrs.Email, ownedEmails)
	if err != nil {
		return nil, err
	}

	err = check(stdattrs.PhoneNumber, ownedPhoneNumbers)
	if err != nil {
		return nil, err
	}

	err = check(stdattrs.PreferredUsername, ownedPreferredUsernames)
	if err != nil {
		return nil, err
	}

	// In case email/phone_number/preferred_username was removed, we add them back.
	stdAttrs, _ = s.PopulateIdentityAwareStandardAttributes0(stdAttrs, identities)

	return stdAttrs, nil
}

func (s *ServiceNoEvent) UpdateStandardAttributes(role accesscontrol.Role, userID string, stdAttrs map[string]interface{}) error {
	u, err := s.UserQueries.GetRaw(userID)
	if err != nil {
		return err
	}

	identities, err := s.Identities.ListByUser(userID)
	if err != nil {
		return err
	}

	stdAttrs, err = s.UpdateStandardAttributes0(role, u, identities, stdAttrs)
	if err != nil {
		return err
	}

	err = s.UserStore.UpdateStandardAttributes(userID, stdAttrs)
	if err != nil {
		return err
	}

	return nil
}

// Batch implementation of DeriveStandardAttributes
// TODO: Write some tests and simplify the implementation
// nolint:gocognit
func (s *ServiceNoEvent) DeriveStandardAttributesForUsers(
	role accesscontrol.Role,
	userIDs []string,
	updatedAts []time.Time,
	attrsList []map[string]interface{},
) (map[string]map[string]interface{}, error) {

	if len(userIDs) != len(updatedAts) || len(userIDs) != len(attrsList) {
		panic("stdattrs: expeceted same length of arguments")
	}

	allClaims, err := s.ClaimStore.ListByUserIDsAndClaimNames(
		userIDs, []string{stdattrs.Email, stdattrs.PhoneNumber})
	if err != nil {
		return nil, err
	}

	claimsByUserID := map[string][]*verification.Claim{}
	for _, c := range allClaims {
		claimsByUserID[c.UserID] = append(claimsByUserID[c.UserID], c)
	}

	result := map[string]map[string]interface{}{}

	for idx, userID := range userIDs {
		attrs := attrsList[idx]
		userClaims := claimsByUserID[userID]
		updatedAt := updatedAts[idx]
		out := make(map[string]interface{})
		for key, value := range attrs {
			value, err := s.Transformer.StorageFormToRepresentationForm(key, value)
			if err != nil {
				return nil, err
			}

			// Copy
			out[key] = value

			// Email
			if key == stdattrs.Email {
				verified := false
				if str, ok := value.(string); ok {
					for _, claim := range userClaims {
						if claim.Name != stdattrs.Email {
							continue
						}
						if claim.Value == str {
							verified = true
						}
					}
				}
				out[stdattrs.EmailVerified] = verified
			}

			// Phone number
			if key == stdattrs.PhoneNumber {
				verified := false
				if str, ok := value.(string); ok {
					for _, claim := range userClaims {
						if claim.Name != stdattrs.PhoneNumber {
							continue
						}
						if claim.Value == str {
							verified = true
						}
					}
				}
				out[stdattrs.PhoneNumberVerified] = verified
			}
		}

		// updated_at
		out[stdattrs.UpdatedAt] = updatedAt.Unix()

		accessControl := s.UserProfileConfig.StandardAttributes.GetAccessControl()
		out = stdattrs.T(out).ReadWithAccessControl(
			accessControl,
			role,
		).ToClaims()

		result[userID] = out
	}

	return result, nil
}

// DeriveStandardAttributes populates email_verified and phone_number_verified,
// if email or phone_number are found in attrs.
func (s *ServiceNoEvent) DeriveStandardAttributes(
	role accesscontrol.Role,
	userID string,
	updatedAt time.Time,
	attrs map[string]interface{},
) (map[string]interface{}, error) {
	result, err := s.DeriveStandardAttributesForUsers(role,
		[]string{userID},
		[]time.Time{updatedAt},
		[]map[string]interface{}{attrs},
	)
	if err != nil {
		return nil, err
	}
	return result[userID], nil
}
