package passkey

import (
	"bytes"
	"context"
	"encoding/base64"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/authgear/authgear-server/pkg/api/model"
)

type Service struct {
	Store         *Store
	ConfigService *ConfigService
}

func (s *Service) PeekAttestationResponse(ctx context.Context, attestationResponse []byte) (creationOptions *model.WebAuthnCreationOptions, credentialID string, signCount int64, err error) {
	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(attestationResponse))
	if err != nil {
		return
	}

	challengeString := parsed.Response.CollectedClientData.Challenge
	challenge, err := base64.RawURLEncoding.DecodeString(challengeString)
	if err != nil {
		return
	}

	session, err := s.Store.PeekSession(ctx, challenge)
	if err != nil {
		return
	}

	creationOptions = session.CreationOptions
	credentialID = parsed.ID
	signCount = int64(parsed.Response.AttestationObject.AuthData.Counter)
	return
}

func (s *Service) ConsumeAttestationResponse(ctx context.Context, attestationResponse []byte) (err error) {
	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(attestationResponse))
	if err != nil {
		return
	}

	challengeString := parsed.Response.CollectedClientData.Challenge
	challenge, err := base64.RawURLEncoding.DecodeString(challengeString)
	if err != nil {
		return
	}

	_, err = s.Store.ConsumeSession(ctx, challenge)
	if err != nil {
		return
	}

	return
}

func (s *Service) GetCredentialIDFromAssertionResponse(ctx context.Context, assertionResponse []byte) (credentialID string, err error) {
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(assertionResponse))
	if err != nil {
		return
	}

	challengeString := parsed.Response.CollectedClientData.Challenge
	challenge, err := base64.RawURLEncoding.DecodeString(challengeString)
	if err != nil {
		return
	}

	_, err = s.Store.PeekSession(ctx, challenge)
	if err != nil {
		return
	}

	credentialID = parsed.ID
	return
}

func (s *Service) PeekAssertionResponse(ctx context.Context, assertionResponse []byte, attestationResponse []byte) (signCount int64, err error) {
	config, err := s.ConfigService.MakeConfig(ctx)
	if err != nil {
		return
	}

	parsedAssertion, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(assertionResponse))
	if err != nil {
		return
	}

	challengeString := parsedAssertion.Response.CollectedClientData.Challenge
	challenge, err := base64.RawURLEncoding.DecodeString(challengeString)
	if err != nil {
		return
	}

	_, err = s.Store.PeekSession(ctx, challenge)
	if err != nil {
		return
	}

	parsedAttestation, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(attestationResponse))
	if err != nil {
		return
	}

	credentialBytes := parsedAttestation.Response.AttestationObject.AuthData.AttData.CredentialPublicKey

	err = parsedAssertion.Verify(
		challengeString,                            // storedChallenge
		config.RPID,                                // relyingPartyID
		[]string{config.RPOrigin},                  // rpOrigins
		[]string{config.RPOrigin},                  // rpTopOrigins. Related to iframe. Since we do not expect being iframe by any website, the top origins is the same as rpOrigins.
		protocol.TopOriginExplicitVerificationMode, // This means top origin must be listed in rpTopOrigins.
		"",    // We do not support FIDO AppID extension
		false, // User verification is preferred so we do not require user verification here.
		credentialBytes,
	)
	if err != nil {
		return
	}

	signCount = int64(parsedAssertion.Response.AuthenticatorData.Counter)
	return
}

func (s *Service) ConsumeAssertionResponse(ctx context.Context, assertionResponse []byte) (err error) {
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(assertionResponse))
	if err != nil {
		return
	}

	challengeString := parsed.Response.CollectedClientData.Challenge
	challenge, err := base64.RawURLEncoding.DecodeString(challengeString)
	if err != nil {
		return
	}

	_, err = s.Store.ConsumeSession(ctx, challenge)
	if err != nil {
		return
	}

	return
}
