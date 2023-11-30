package workflow

import (
	"net/http"
	"time"

	"github.com/authgear/authgear-server/pkg/api/event"
	"github.com/authgear/authgear-server/pkg/api/model"
	"github.com/authgear/authgear-server/pkg/lib/accountmigration"
	"github.com/authgear/authgear-server/pkg/lib/accounts"
	"github.com/authgear/authgear-server/pkg/lib/authn/attrs"
	"github.com/authgear/authgear-server/pkg/lib/authn/authenticationinfo"
	"github.com/authgear/authgear-server/pkg/lib/authn/authenticator"
	"github.com/authgear/authgear-server/pkg/lib/authn/identity"
	"github.com/authgear/authgear-server/pkg/lib/authn/mfa"
	"github.com/authgear/authgear-server/pkg/lib/authn/otp"
	"github.com/authgear/authgear-server/pkg/lib/authn/user"
	"github.com/authgear/authgear-server/pkg/lib/config"
	"github.com/authgear/authgear-server/pkg/lib/feature/forgotpassword"
	"github.com/authgear/authgear-server/pkg/lib/feature/verification"
	"github.com/authgear/authgear-server/pkg/lib/oauth"
	"github.com/authgear/authgear-server/pkg/lib/ratelimit"
	"github.com/authgear/authgear-server/pkg/lib/session"
	"github.com/authgear/authgear-server/pkg/lib/session/idpsession"
	"github.com/authgear/authgear-server/pkg/util/accesscontrol"
	"github.com/authgear/authgear-server/pkg/util/clock"
	"github.com/authgear/authgear-server/pkg/util/httputil"
)

type AccountService interface {
	// User Create
	NewUser(id string) *user.User
	UpdateUserLoginTime(u *user.User, loginAt time.Time) *user.User

	// User Read
	GetUserByID(id string) (*user.User, error)

	// User Update
	PopulateStandardAttribute(u *user.User, info *identity.Info) *user.User
	UpdateStandardAttributesWithList(role accesscontrol.Role, u *user.User, identities []*identity.Info, attrs attrs.List) (*user.User, error)

	// Identity Create
	GetNewIdentityChanges(spec *identity.Spec, u *user.User, identities []*identity.Info, claims []*verification.Claim) (*accounts.NewIdentityChanges, error)

	// Identity Read
	GetIdentityByID(id string) (*identity.Info, error)
	SearchIdentities(spec *identity.Spec) (exactMatch *identity.Info, otherMatches []*identity.Info, err error)
	ListIdentitiesByClaim(name string, value string) ([]*identity.Info, error)
	ListIdentitiesOfUser(userID string) ([]*identity.Info, error)
	FindDuplicatedIdentity(info *identity.Info) (*identity.Info, error)

	// Identity Update
	GetUpdateIdentityChanges(
		info *identity.Info,
		spec *identity.Spec,
		u *user.User,
		identities []*identity.Info,
		authenticators []*authenticator.Info,
		claims []*verification.Claim,
	) (*accounts.UpdateIdentityChanges, error)

	// Authenticator Create
	NewAuthenticator(spec *authenticator.Spec) (*authenticator.Info, error)

	// Authenticator Read
	ListAuthenticatorsOfUser(userID string) ([]*authenticator.Info, error)

	// Authenticator Update
	UpdateAuthenticatorWithSpec(info *authenticator.Info, spec *authenticator.Spec) (bool, *authenticator.Info, error)
	VerifyAuthenticatorsWithSpec(infos []*authenticator.Info, spec *authenticator.Spec, options *accounts.VerifyAuthenticatorOptions) (*accounts.VerifyAuthenticatorResult, error)
	ResetPrimaryPassword(infos []*authenticator.Info, state *otp.State, newPassword string) (*accounts.ResetPrimaryPasswordResult, error)

	// VerifiedClaim Create
	NewVerifiedClaim(existingClaims []*verification.Claim, userID string, claimName string, claimValue string) (*verification.Claim, bool)

	// VerifiedClaim Read
	ListVerifiedClaimsOfUser(userID string) ([]*verification.Claim, error)
	GetIdentityVerificationStatus(info *identity.Info, claims []*verification.Claim) ([]verification.ClaimStatus, error)
}

type AccountWriter interface {
	CreateUser(u *user.User) error
	UpdateUser(u *user.User) error

	CreateIdentity(info *identity.Info) error
	UpdateIdentity(info *identity.Info) error

	CreateAuthenticator(info *authenticator.Info) error
	UpdateAuthenticator(info *authenticator.Info) error
	DeleteAuthenticator(info *authenticator.Info) error

	CreateVerifiedClaim(claim *verification.Claim) error
	DeleteVerifiedClaim(claim *verification.Claim) error
}

type LockoutService interface {
	ClearAttempts(userID string, usedMethods []config.AuthenticationLockoutMethod) error
}

type OTPCodeService interface {
	GenerateOTP(kind otp.Kind, target string, form otp.Form, opt *otp.GenerateOptions) (string, error)
	VerifyOTP(kind otp.Kind, target string, otp string, opts *otp.VerifyOptions) error
	InspectState(kind otp.Kind, target string) (*otp.State, error)

	LookupCode(purpose otp.Purpose, code string) (target string, err error)
	SetSubmittedCode(kind otp.Kind, target string, code string) (*otp.State, error)
}

type OTPSender interface {
	Prepare(channel model.AuthenticatorOOBChannel, target string, form otp.Form, typ otp.MessageType) (*otp.PreparedMessage, error)
	Send(msg *otp.PreparedMessage, opts otp.SendOptions) error
}

type ForgotPasswordService interface {
	SendCode(loginID string, options *forgotpassword.CodeOptions) error
}

type ResetPasswordService interface {
	VerifyCode(code string) (state *otp.State, err error)
}

type RateLimiter interface {
	Allow(spec ratelimit.BucketSpec) error
	Reserve(spec ratelimit.BucketSpec) *ratelimit.Reservation
	Cancel(r *ratelimit.Reservation)
}

type EventService interface {
	DispatchEvent(payload event.Payload) error
	DispatchErrorEvent(payload event.NonBlockingPayload) error
}

type IDPSessionService interface {
	MakeSession(*session.Attrs) (*idpsession.IDPSession, string)
	Create(*idpsession.IDPSession) error
	Reauthenticate(idpSessionID string, amr []string) error
}

type SessionService interface {
	RevokeWithoutEvent(session.Session) error
}

type AuthenticationInfoService interface {
	Save(entry *authenticationinfo.Entry) error
}

type CookieManager interface {
	GetCookie(r *http.Request, def *httputil.CookieDef) (*http.Cookie, error)
	ValueCookie(def *httputil.CookieDef, value string) *http.Cookie
	ClearCookie(def *httputil.CookieDef) *http.Cookie
}

type EventStore interface {
	Publish(workflowID string, e Event) error
}

type AccountMigrationService interface {
	Run(migrationTokenString string) (*accountmigration.HookResponse, error)
}

type CaptchaService interface {
	VerifyToken(token string) error
}

type OfflineGrantStore interface {
	ListClientOfflineGrants(clientID string, userID string) ([]*oauth.OfflineGrant, error)
}

type Dependencies struct {
	Config        *config.AppConfig
	FeatureConfig *config.FeatureConfig

	Clock    clock.Clock
	RemoteIP httputil.RemoteIP

	HTTPRequest *http.Request

	Accounts      AccountService
	AccountWriter AccountWriter
	Lockout       LockoutService

	OTPCodes          OTPCodeService
	OTPSender         OTPSender
	ForgotPassword    ForgotPasswordService
	ResetPassword     ResetPasswordService
	AccountMigrations AccountMigrationService
	Captcha           CaptchaService

	IDPSessions          IDPSessionService
	Sessions             SessionService
	AuthenticationInfos  AuthenticationInfoService
	SessionCookie        session.CookieDef
	MFADeviceTokenCookie mfa.CookieDef

	Cookies CookieManager

	Events         EventService
	RateLimiter    RateLimiter
	WorkflowEvents EventStore

	OfflineGrants OfflineGrantStore
}
