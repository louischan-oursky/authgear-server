package sso

import (
	"github.com/skygeario/skygear-server/pkg/core/config"
)

// AuthInfo contains auth info from HandleAuthzResp
type AuthInfo struct {
	ProviderConfig          config.OAuthProviderConfiguration
	ProviderRawProfile      map[string]interface{}
	ProviderAccessTokenResp interface{}
	ProviderUserInfo        ProviderUserInfo
}

type ProviderUserInfo struct {
	ID string
	// Email is normalized.
	Email string
}

func (i ProviderUserInfo) ClaimsValue() map[string]interface{} {
	claimsValue := map[string]interface{}{}
	if i.Email != "" {
		claimsValue["email"] = i.Email
	}
	return claimsValue
}

type OAuthAuthorizationResponse struct {
	Code  string
	State string
	Scope string
}

type getAuthInfoRequest struct {
	redirectURL     string
	oauthConfig     *config.OAuthConfiguration
	providerConfig  config.OAuthProviderConfiguration
	accessTokenURL  string
	userProfileURL  string
	userInfoDecoder UserInfoDecoder
}

func (h getAuthInfoRequest) getAuthInfo(r OAuthAuthorizationResponse, state State) (authInfo AuthInfo, err error) {
	// compare nonce
	authInfo = AuthInfo{
		ProviderConfig: h.providerConfig,
	}

	accessTokenResp, err := fetchAccessTokenResp(
		r.Code,
		h.accessTokenURL,
		h.redirectURL,
		h.oauthConfig,
		h.providerConfig,
	)
	if err != nil {
		return
	}
	authInfo.ProviderAccessTokenResp = accessTokenResp

	return h.getAuthInfoByAccessTokenResp(accessTokenResp)
}

func (h getAuthInfoRequest) getAuthInfoByAccessTokenResp(accessTokenResp AccessTokenResp) (authInfo AuthInfo, err error) {
	authInfo = AuthInfo{
		ProviderConfig: h.providerConfig,
		// validated accessTokenResp
		ProviderAccessTokenResp: accessTokenResp,
	}

	userProfile, err := fetchUserProfile(accessTokenResp, h.userProfileURL)
	if err != nil {
		return
	}
	authInfo.ProviderRawProfile = userProfile
	providerUserInfo, err := h.userInfoDecoder.DecodeUserInfo(h.providerConfig.Type, userProfile)
	if err != nil {
		return
	}
	authInfo.ProviderUserInfo = *providerUserInfo

	return
}
