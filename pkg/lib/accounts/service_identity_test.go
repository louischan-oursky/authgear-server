package accounts

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/authgear/authgear-server/pkg/api/model"
	"github.com/authgear/authgear-server/pkg/lib/authn/authenticator"
	"github.com/authgear/authgear-server/pkg/lib/authn/identity"
	"github.com/authgear/authgear-server/pkg/lib/authn/user"
	"github.com/authgear/authgear-server/pkg/lib/config"
	"github.com/authgear/authgear-server/pkg/lib/feature/verification"
	"github.com/authgear/authgear-server/pkg/util/clock"
)

type deepEqualMatcher struct {
	Value interface{}
}

var _ gomock.Matcher = deepEqualMatcher{}

func (m deepEqualMatcher) Matches(x interface{}) bool {
	return reflect.DeepEqual(m.Value, x)
}

func (m deepEqualMatcher) String() string {
	return fmt.Sprintf("%v", m.Value)
}

func deepEqual(v interface{}) deepEqualMatcher {
	return deepEqualMatcher{v}
}

func newBool(b bool) *bool {
	return &b
}

func newUserNoAttrs(id string) *user.User {
	return &user.User{
		ID:                 id,
		StandardAttributes: map[string]interface{}{},
		CustomAttributes:   map[string]interface{}{},
	}
}

func newUser(id string, email string) *user.User {
	return &user.User{
		ID: id,
		StandardAttributes: map[string]interface{}{
			"email": email,
		},
		CustomAttributes: map[string]interface{}{},
	}
}

func newEmailLoginIDIdentity(id string, userID string, email string) *identity.Info {
	return &identity.Info{
		ID:     id,
		UserID: userID,
		Type:   model.IdentityTypeLoginID,
		LoginID: &identity.LoginID{
			ID:              id,
			UserID:          userID,
			LoginIDKey:      "email",
			LoginIDType:     model.LoginIDKeyTypeEmail,
			LoginID:         email,
			OriginalLoginID: email,
			UniqueKey:       email,
			Claims: map[string]interface{}{
				"email": email,
			},
		},
	}
}

func newPhoneLoginIDIdentity(id string, userID string, phone string) *identity.Info {
	return &identity.Info{
		ID:     id,
		UserID: userID,
		Type:   model.IdentityTypeLoginID,
		LoginID: &identity.LoginID{
			ID:              id,
			UserID:          userID,
			LoginIDKey:      "phone",
			LoginIDType:     model.LoginIDKeyTypePhone,
			LoginID:         phone,
			OriginalLoginID: phone,
			UniqueKey:       phone,
			Claims: map[string]interface{}{
				"phone_number": phone,
			},
		},
	}
}

func newOAuthGoogleIdentity(id string, userID string, googleID string, email string) *identity.Info {
	return &identity.Info{
		ID:     id,
		UserID: userID,
		Type:   model.IdentityTypeOAuth,
		OAuth: &identity.OAuth{
			ID:     id,
			UserID: userID,
			ProviderID: config.ProviderID{
				Type: "google",
			},
			ProviderSubjectID: googleID,
			UserProfile: map[string]interface{}{
				"email": email,
			},
			Claims: map[string]interface{}{
				"email": email,
			},
		},
	}
}

func newPrimaryPasswordAuthenticator(id string, userID string, hash string) *authenticator.Info {
	return &authenticator.Info{
		ID:     id,
		UserID: userID,
		Type:   model.AuthenticatorTypePassword,
		Kind:   authenticator.KindPrimary,
		Password: &authenticator.Password{
			ID:           id,
			UserID:       userID,
			Kind:         string(authenticator.KindPrimary),
			PasswordHash: []byte(hash),
		},
	}
}

func newPrimaryOOBOTPEmailAuthenticator(id string, userID string, email string) *authenticator.Info {
	return &authenticator.Info{
		ID:     id,
		UserID: userID,
		Type:   model.AuthenticatorTypeOOBEmail,
		Kind:   authenticator.KindPrimary,
		OOBOTP: &authenticator.OOBOTP{
			ID:                   id,
			UserID:               userID,
			OOBAuthenticatorType: model.AuthenticatorTypeOOBEmail,
			Kind:                 string(authenticator.KindPrimary),
			Email:                email,
		},
	}
}

func newSecondaryOOBOTPEmailAuthenticator(id string, userID string, email string) *authenticator.Info {
	return &authenticator.Info{
		ID:     id,
		UserID: userID,
		Type:   model.AuthenticatorTypeOOBEmail,
		Kind:   authenticator.KindSecondary,
		OOBOTP: &authenticator.OOBOTP{
			ID:                   id,
			UserID:               userID,
			OOBAuthenticatorType: model.AuthenticatorTypeOOBEmail,
			Kind:                 string(authenticator.KindSecondary),
			Email:                email,
		},
	}
}

func newPrimaryOOBOTPSMSAuthenticator(id string, userID string, phone string) *authenticator.Info {
	return &authenticator.Info{
		ID:     id,
		UserID: userID,
		Type:   model.AuthenticatorTypeOOBSMS,
		Kind:   authenticator.KindPrimary,
		OOBOTP: &authenticator.OOBOTP{
			ID:                   id,
			UserID:               userID,
			OOBAuthenticatorType: model.AuthenticatorTypeOOBSMS,
			Kind:                 string(authenticator.KindPrimary),
			Phone:                phone,
		},
	}
}

func newVerifiedClaim(id string, userID string, name string, value string) *verification.Claim {
	return &verification.Claim{
		ID:     id,
		UserID: userID,
		Name:   name,
		Value:  value,
	}
}

func TestGetNewIdentityChanges(t *testing.T) {
	Convey("GetNewIdentityChanges", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		loginIDIdentities := NewMockLoginIDIdentities(ctrl)
		oauthIdentities := NewMockOAuthIdentities(ctrl)
		standardAttributes := NewMockStandardAttributes(ctrl)

		s := &Service{
			StandardAttributes: standardAttributes,
			LoginIDIdentities:  loginIDIdentities,
			OAuthIdentities:    oauthIdentities,
			IdentityConfig: &config.IdentityConfig{
				OAuth: &config.OAuthSSOConfig{
					Providers: []config.OAuthSSOProviderConfig{
						{
							Alias: "google",
							Type:  config.OAuthSSOProviderTypeGoogle,
							Claims: &config.OAuthClaimsConfig{
								Email: &config.OAuthClaimConfig{
									AssumeVerified: newBool(true),
								},
							},
						},
					},
				},
			},
			Clock: clock.NewMockClock(),
		}

		Convey("new login id identity", func() {
			spec := &identity.Spec{
				Type: model.IdentityTypeLoginID,
				LoginID: &identity.LoginIDSpec{
					Key:   "email",
					Type:  model.LoginIDKeyTypeEmail,
					Value: "user@example.com",
				},
			}
			loginIDIdentities.EXPECT().New("user0", *spec.LoginID, gomock.Any()).Times(1).Return(
				newEmailLoginIDIdentity("identity0", "user0", "user@example.com").LoginID, nil,
			)
			standardAttributes.EXPECT().PopulateIdentityAwareStandardAttributes0(deepEqual(map[string]interface{}{}), deepEqual([]*identity.Info{
				newEmailLoginIDIdentity("identity0", "user0", "user@example.com"),
			})).Times(1).Return(
				map[string]interface{}{
					"email": "user@example.com",
				},
				true,
			)

			changes, err := s.GetNewIdentityChanges(
				spec,
				newUserNoAttrs("user0"),
				[]*identity.Info{},
				[]*verification.Claim{},
			)
			So(err, ShouldBeNil)
			So(changes, ShouldResemble, &NewIdentityChanges{
				UpdatedUser: newUser("user0", "user@example.com"),
				NewIdentity: newEmailLoginIDIdentity("identity0", "user0", "user@example.com"),
			})
		})

		Convey("new oauth identity", func() {
			spec := &identity.Spec{
				Type: model.IdentityTypeOAuth,
				OAuth: &identity.OAuthSpec{
					ProviderID: config.ProviderID{
						Type: "google",
					},
					SubjectID: "google0",
					RawProfile: map[string]interface{}{
						"email": "user@gmail.com",
					},
					StandardClaims: map[string]interface{}{
						"email": "user@gmail.com",
					},
				},
			}
			oauthIdentities.EXPECT().New(
				"user0",
				config.ProviderID{
					Type: "google",
				},
				"google0",
				map[string]interface{}{
					"email": "user@gmail.com",
				},
				map[string]interface{}{
					"email": "user@gmail.com",
				},
			).Times(1).Return(
				newOAuthGoogleIdentity("identity0", "user0", "google0", "user@gmail.com").OAuth,
			)
			standardAttributes.EXPECT().PopulateIdentityAwareStandardAttributes0(deepEqual(map[string]interface{}{}), deepEqual([]*identity.Info{
				newOAuthGoogleIdentity("identity0", "user0", "google0", "user@gmail.com"),
			})).Times(1).Return(
				map[string]interface{}{
					"email": "user@gmail.com",
				},
				true,
			)

			changes, err := s.GetNewIdentityChanges(
				spec,
				newUserNoAttrs("user0"),
				[]*identity.Info{},
				[]*verification.Claim{},
			)
			So(err, ShouldBeNil)
			expected := &NewIdentityChanges{
				UpdatedUser: newUser("user0", "user@gmail.com"),
				NewIdentity: newOAuthGoogleIdentity("identity0", "user0", "google0", "user@gmail.com"),
				NewVerifiedClaims: []*verification.Claim{
					newVerifiedClaim("", "user0", "email", "user@gmail.com"),
				},
			}
			So(changes.UpdatedUser, ShouldResemble, expected.UpdatedUser)
			So(changes.NewIdentity, ShouldResemble, expected.NewIdentity)
			So(len(changes.NewVerifiedClaims), ShouldEqual, 1)
			So(changes.NewVerifiedClaims[0].Value, ShouldEqual, expected.NewVerifiedClaims[0].Value)
		})
	})
}

func TestGetUpdateIdentityChanges(t *testing.T) {
	Convey("GetUpdateIdentityChanges", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		loginIDIdentities := NewMockLoginIDIdentities(ctrl)
		oauthIdentities := NewMockOAuthIdentities(ctrl)
		oobotpAuthenticators := NewMockOOBOTPAuthenticators(ctrl)
		standardAttributes := NewMockStandardAttributes(ctrl)

		s := &Service{
			StandardAttributes:   standardAttributes,
			LoginIDIdentities:    loginIDIdentities,
			OAuthIdentities:      oauthIdentities,
			OOBOTPAuthenticators: oobotpAuthenticators,
			IdentityConfig: &config.IdentityConfig{
				OAuth: &config.OAuthSSOConfig{
					Providers: []config.OAuthSSOProviderConfig{
						{
							Alias: "google",
							Type:  config.OAuthSSOProviderTypeGoogle,
							Claims: &config.OAuthClaimsConfig{
								Email: &config.OAuthClaimConfig{
									AssumeVerified: newBool(true),
								},
							},
						},
					},
				},
			},
			Clock: clock.NewMockClock(),
		}

		Convey("Update login ID with no authenticators, claims", func() {
			loginIDIdentities.EXPECT().WithValue(gomock.Any(), "user+1@example.com", gomock.Any()).Times(1).Return(
				newEmailLoginIDIdentity("identity0", "user0", "user+1@example.com").LoginID, nil,
			)
			standardAttributes.EXPECT().PopulateIdentityAwareStandardAttributes0(deepEqual(map[string]interface{}{
				"email": "user@example.com",
			}), deepEqual([]*identity.Info{
				newEmailLoginIDIdentity("identity0", "user0", "user+1@example.com"),
				newPhoneLoginIDIdentity("identity1", "user0", "+85251000000"),
			})).Times(1).Return(
				map[string]interface{}{
					"email": "user+1@example.com",
				},
				true,
			)

			changes, err := s.GetUpdateIdentityChanges(
				newEmailLoginIDIdentity("identity0", "user0", "user@example.com"),
				&identity.Spec{
					LoginID: &identity.LoginIDSpec{
						Value: "user+1@example.com",
					},
				},
				newUser("user0", "user@example.com"),
				[]*identity.Info{
					newEmailLoginIDIdentity("identity0", "user0", "user@example.com"),
					newPhoneLoginIDIdentity("identity1", "user0", "+85251000000"),
				},
				[]*authenticator.Info{},
				[]*verification.Claim{},
			)
			So(err, ShouldBeNil)
			So(changes, ShouldResemble, &UpdateIdentityChanges{
				UpdatedUser:     newUser("user0", "user+1@example.com"),
				UpdatedIdentity: newEmailLoginIDIdentity("identity0", "user0", "user+1@example.com"),
			})
		})

		Convey("Update login ID; do not update standard attributes if the updating identity does not contribute to standard attributes", func() {
			loginIDIdentities.EXPECT().WithValue(gomock.Any(), "user+1@example.com", gomock.Any()).Times(1).Return(
				newEmailLoginIDIdentity("identity0", "user0", "user+1@example.com").LoginID, nil,
			)
			standardAttributes.EXPECT().PopulateIdentityAwareStandardAttributes0(deepEqual(map[string]interface{}{
				"email": "johndoe@example.com",
			}), deepEqual([]*identity.Info{
				newEmailLoginIDIdentity("identity0", "user0", "user+1@example.com"),
				newEmailLoginIDIdentity("identity1", "user0", "johndoe@example.com"),
			})).Times(1).Return(
				map[string]interface{}{
					"email": "johndoe@example.com",
				},
				false,
			)

			changes, err := s.GetUpdateIdentityChanges(
				newEmailLoginIDIdentity("identity0", "user0", "user@example.com"),
				&identity.Spec{
					LoginID: &identity.LoginIDSpec{
						Value: "user+1@example.com",
					},
				},
				newUser("user0", "johndoe@example.com"),
				[]*identity.Info{
					newEmailLoginIDIdentity("identity0", "user0", "user@example.com"),
					newEmailLoginIDIdentity("identity1", "user0", "johndoe@example.com"),
				},
				[]*authenticator.Info{},
				[]*verification.Claim{},
			)
			So(err, ShouldBeNil)
			So(changes, ShouldResemble, &UpdateIdentityChanges{
				UpdatedIdentity: newEmailLoginIDIdentity("identity0", "user0", "user+1@example.com"),
			})
		})

		Convey("Update login ID with dependent authenticators", func() {
			loginIDIdentities.EXPECT().WithValue(gomock.Any(), "user+1@example.com", gomock.Any()).Times(1).Return(
				newEmailLoginIDIdentity("identity0", "user0", "user+1@example.com").LoginID, nil,
			)
			oobotpAuthenticators.EXPECT().WithSpec(gomock.Any(), &authenticator.OOBOTPSpec{
				Email: "user+1@example.com",
			}).Times(1).Return(
				newPrimaryOOBOTPEmailAuthenticator("oobotp0", "user0", "user+1@example.com").OOBOTP, nil,
			)
			standardAttributes.EXPECT().PopulateIdentityAwareStandardAttributes0(deepEqual(map[string]interface{}{
				"email": "user@example.com",
			}), deepEqual([]*identity.Info{
				newEmailLoginIDIdentity("identity0", "user0", "user+1@example.com"),
				newPhoneLoginIDIdentity("identity1", "user0", "+85251000000"),
			})).Times(1).Return(
				map[string]interface{}{
					"email": "user+1@example.com",
				},
				true,
			)

			changes, err := s.GetUpdateIdentityChanges(
				newEmailLoginIDIdentity("identity0", "user0", "user@example.com"),
				&identity.Spec{
					LoginID: &identity.LoginIDSpec{
						Value: "user+1@example.com",
					},
				},
				newUser("user0", "user@example.com"),
				[]*identity.Info{
					newEmailLoginIDIdentity("identity0", "user0", "user@example.com"),
					newPhoneLoginIDIdentity("identity1", "user0", "+85251000000"),
				},
				[]*authenticator.Info{
					newPrimaryPasswordAuthenticator("password0", "user0", "hash"),
					newPrimaryOOBOTPEmailAuthenticator("oobotp0", "user0", "user@example.com"),
					newPrimaryOOBOTPSMSAuthenticator("oobotp1", "user0", "+85251000000"),
				},
				[]*verification.Claim{},
			)
			So(err, ShouldBeNil)
			So(changes, ShouldResemble, &UpdateIdentityChanges{
				UpdatedUser:     newUser("user0", "user+1@example.com"),
				UpdatedIdentity: newEmailLoginIDIdentity("identity0", "user0", "user+1@example.com"),
				UpdatedAuthenticators: []*authenticator.Info{
					newPrimaryOOBOTPEmailAuthenticator("oobotp0", "user0", "user+1@example.com"),
				},
			})
		})

		Convey("Update login ID with claims", func() {
			loginIDIdentities.EXPECT().WithValue(gomock.Any(), "user+1@example.com", gomock.Any()).Times(1).Return(
				newEmailLoginIDIdentity("identity0", "user0", "user+1@example.com").LoginID, nil,
			)
			standardAttributes.EXPECT().PopulateIdentityAwareStandardAttributes0(deepEqual(map[string]interface{}{
				"email": "user@example.com",
			}), deepEqual([]*identity.Info{
				newEmailLoginIDIdentity("identity0", "user0", "user+1@example.com"),
				newPhoneLoginIDIdentity("identity1", "user0", "+85251000000"),
			})).Times(1).Return(
				map[string]interface{}{
					"email": "user+1@example.com",
				},
				true,
			)

			changes, err := s.GetUpdateIdentityChanges(
				newEmailLoginIDIdentity("identity0", "user0", "user@example.com"),
				&identity.Spec{
					LoginID: &identity.LoginIDSpec{
						Value: "user+1@example.com",
					},
				},
				newUser("user0", "user@example.com"),
				[]*identity.Info{
					newEmailLoginIDIdentity("identity0", "user0", "user@example.com"),
					newPhoneLoginIDIdentity("identity1", "user0", "+85251000000"),
				},
				[]*authenticator.Info{},
				[]*verification.Claim{
					newVerifiedClaim("claim0", "user0", "email", "user@example.com"),
					newVerifiedClaim("claim1", "user0", "phone_number", "+85251000000"),
				},
			)
			So(err, ShouldBeNil)
			So(changes, ShouldResemble, &UpdateIdentityChanges{
				UpdatedUser:     newUser("user0", "user+1@example.com"),
				UpdatedIdentity: newEmailLoginIDIdentity("identity0", "user0", "user+1@example.com"),
				RemovedVerifiedClaims: []*verification.Claim{
					newVerifiedClaim("claim0", "user0", "email", "user@example.com"),
				},
			})
		})

		Convey("Update login ID; do not remove claims that are still referenced", func() {
			loginIDIdentities.EXPECT().WithValue(gomock.Any(), "user+1@example.com", gomock.Any()).Times(1).Return(
				newEmailLoginIDIdentity("identity0", "user0", "user+1@example.com").LoginID, nil,
			)
			oobotpAuthenticators.EXPECT().WithSpec(gomock.Any(), &authenticator.OOBOTPSpec{
				Email: "user+1@example.com",
			}).Times(1).Return(
				newPrimaryOOBOTPEmailAuthenticator("oobotp0", "user0", "user+1@example.com").OOBOTP, nil,
			)
			standardAttributes.EXPECT().PopulateIdentityAwareStandardAttributes0(deepEqual(map[string]interface{}{
				"email": "user@example.com",
			}), deepEqual([]*identity.Info{
				newEmailLoginIDIdentity("identity0", "user0", "user+1@example.com"),
				newPhoneLoginIDIdentity("identity1", "user0", "+85251000000"),
			})).Times(1).Return(
				map[string]interface{}{
					"email": "user+1@example.com",
				},
				true,
			)

			changes, err := s.GetUpdateIdentityChanges(
				newEmailLoginIDIdentity("identity0", "user0", "user@example.com"),
				&identity.Spec{
					LoginID: &identity.LoginIDSpec{
						Value: "user+1@example.com",
					},
				},
				newUser("user0", "user@example.com"),
				[]*identity.Info{
					newEmailLoginIDIdentity("identity0", "user0", "user@example.com"),
					newPhoneLoginIDIdentity("identity1", "user0", "+85251000000"),
				},
				[]*authenticator.Info{
					newPrimaryPasswordAuthenticator("password0", "user0", "hash"),
					newPrimaryOOBOTPEmailAuthenticator("oobotp0", "user0", "user@example.com"),
					newPrimaryOOBOTPSMSAuthenticator("oobotp1", "user0", "+85251000000"),
					newSecondaryOOBOTPEmailAuthenticator("oobotp2", "user0", "user@example.com"),
				},
				[]*verification.Claim{
					newVerifiedClaim("claim0", "user0", "email", "user@example.com"),
				},
			)
			So(err, ShouldBeNil)
			So(changes, ShouldResemble, &UpdateIdentityChanges{
				UpdatedUser:     newUser("user0", "user+1@example.com"),
				UpdatedIdentity: newEmailLoginIDIdentity("identity0", "user0", "user+1@example.com"),
				UpdatedAuthenticators: []*authenticator.Info{
					newPrimaryOOBOTPEmailAuthenticator("oobotp0", "user0", "user+1@example.com"),
				},
			})
		})

		Convey("Update oauth; verify email automatically", func() {
			spec := &identity.OAuthSpec{
				RawProfile: map[string]interface{}{
					"email": "user+1@gmail.com",
				},
				StandardClaims: map[string]interface{}{
					"email": "user+1@gmail.com",
				},
			}

			oauthIdentities.EXPECT().WithUpdate(gomock.Any(), spec.RawProfile, spec.StandardClaims).Times(1).Return(
				newOAuthGoogleIdentity("identity0", "user0", "google0", "user+1@gmail.com").OAuth,
			)
			standardAttributes.EXPECT().PopulateIdentityAwareStandardAttributes0(deepEqual(map[string]interface{}{
				"email": "user@gmail.com",
			}), deepEqual([]*identity.Info{
				newOAuthGoogleIdentity("identity0", "user0", "google0", "user+1@gmail.com"),
			})).Times(1).Return(
				map[string]interface{}{
					"email": "user+1@gmail.com",
				},
				true,
			)

			changes, err := s.GetUpdateIdentityChanges(
				newOAuthGoogleIdentity("identity0", "user0", "google0", "user@gmail.com"),
				&identity.Spec{
					OAuth: spec,
				},
				newUser("user0", "user@gmail.com"),
				[]*identity.Info{
					newOAuthGoogleIdentity("identity0", "user0", "google0", "user@gmail.com"),
				},
				[]*authenticator.Info{},
				[]*verification.Claim{
					newVerifiedClaim("claim0", "user0", "email", "user@gmail.com"),
				},
			)
			So(err, ShouldBeNil)
			expected := &UpdateIdentityChanges{
				UpdatedUser:           newUser("user0", "user+1@gmail.com"),
				UpdatedIdentity:       newOAuthGoogleIdentity("identity0", "user0", "google0", "user+1@gmail.com"),
				NewVerifiedClaims:     []*verification.Claim{newVerifiedClaim("", "user0", "email", "user+1@gmail.com")},
				RemovedVerifiedClaims: []*verification.Claim{newVerifiedClaim("claim0", "user0", "email", "user@gmail.com")},
			}
			So(changes.UpdatedUser, ShouldResemble, expected.UpdatedUser)
			So(changes.UpdatedIdentity, ShouldResemble, expected.UpdatedIdentity)
			So(changes.RemovedVerifiedClaims, ShouldResemble, expected.RemovedVerifiedClaims)
			So(len(changes.NewVerifiedClaims), ShouldEqual, 1)
			So(changes.NewVerifiedClaims[0].Value, ShouldEqual, expected.NewVerifiedClaims[0].Value)
		})
	})
}
