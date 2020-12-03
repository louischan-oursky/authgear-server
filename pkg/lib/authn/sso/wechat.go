package sso

import (
	"errors"
	"net/url"

	"github.com/authgear/authgear-server/pkg/lib/config"
)

const (
	wechatAuthorizationURL string = "https://open.weixin.qq.com/connect/oauth2/authorize"
	wechatTokenURL         string = "https://api.weixin.qq.com/sns/oauth2/access_token"
	wechatUserInfoURL      string = "https://api.weixin.qq.com/sns/userinfo"
)

type WechatImpl struct {
	RedirectURL     RedirectURLProvider
	ProviderConfig  config.OAuthSSOProviderConfig
	Credentials     config.OAuthClientCredentialsItem
	UserInfoDecoder UserInfoDecoder
}

func (*WechatImpl) Type() config.OAuthSSOProviderType {
	return config.OAuthSSOProviderTypeWechat
}

func (f *WechatImpl) Config() config.OAuthSSOProviderConfig {
	return f.ProviderConfig
}

func (f *WechatImpl) GetAuthURL(param GetAuthURLParam) (string, error) {
	v := url.Values{}
	v.Add("response_type", "code")
	v.Add("appid", f.ProviderConfig.ClientID)
	v.Add("redirect_uri", f.RedirectURL.SSOCallbackURL(f.ProviderConfig).String())
	v.Add("scope", f.ProviderConfig.Type.Scope())
	v.Add("state", param.State)
	return wechatAuthorizationURL + "?" + v.Encode(), nil
	// return wechatAuthorizationURL + "?" + v.Encode() + "#wechat_redirect", nil
}

func (f *WechatImpl) GetAuthInfo(r OAuthAuthorizationResponse, param GetAuthInfoParam) (authInfo AuthInfo, err error) {
	return f.NonOpenIDConnectGetAuthInfo(r, param)
}

func (f *WechatImpl) NonOpenIDConnectGetAuthInfo(r OAuthAuthorizationResponse, _ GetAuthInfoParam) (authInfo AuthInfo, err error) {
	err = errors.New("not yet implemented")
	return
}
