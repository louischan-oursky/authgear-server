package accounts

import (
	"github.com/authgear/authgear-server/pkg/api/model"
	"github.com/authgear/authgear-server/pkg/lib/authn/identity"
	"github.com/authgear/authgear-server/pkg/lib/config"
	"github.com/authgear/authgear-server/pkg/lib/feature/verification"
	"github.com/authgear/authgear-server/pkg/util/uuid"
)

func (s *Service) NewVerifiedClaim(userID string, claimName string, claimValue string) *verification.Claim {
	now := s.Clock.NowUTC()
	return &verification.Claim{
		ID:        uuid.New(),
		UserID:    userID,
		Name:      claimName,
		Value:     claimValue,
		CreatedAt: now,
	}
}

func (s *Service) CreateVerifiedClaim(claim *verification.Claim) error {
	return s.VerifiedClaims.Create(claim)
}

func (s *Service) ListVerifiedClaimsOfUser(userID string) ([]*verification.Claim, error) {
	return s.VerifiedClaims.ListByUser(userID)
}

func (s *Service) GetIdentityVerificationStatus(info *identity.Info, claims []*verification.Claim) ([]verification.ClaimStatus, error) {
	var statuses []verification.ClaimStatus

	// Build a map to allow fast indexing.
	byNameByValue := make(map[string]map[string]struct{})
	for _, claim := range claims {
		byValue, ok := byNameByValue[claim.Name]
		if !ok {
			byValue = make(map[string]struct{})
			byNameByValue[claim.Name] = byValue
		}
		byValue[claim.Value] = struct{}{}
	}

	standardClaims := info.IdentityAwareStandardClaims()
	for claimName, claimValue := range standardClaims {
		c := s.getVerificationClaimConfig(claimName)
		if c != nil {
			_, verified := byNameByValue[string(claimName)][claimValue]
			statuses = append(statuses, verification.ClaimStatus{
				Name:                       string(claimName),
				Value:                      claimValue,
				Verified:                   verified,
				RequiredToVerifyOnCreation: *c.Required,
				EndUserTriggerable:         *c.Enabled,
			})
		}
	}

	return statuses, nil
}

func (s *Service) getVerificationClaimConfig(claimName model.ClaimName) *config.VerificationClaimConfig {
	switch claimName {
	case model.ClaimEmail:
		return s.VerificationConfig.Claims.Email
	case model.ClaimPhoneNumber:
		return s.VerificationConfig.Claims.PhoneNumber
	default:
		return nil
	}
}
