package event

import (
	"context"

	"github.com/authgear/authgear-server/pkg/api/event"
	adminauthz "github.com/authgear/authgear-server/pkg/lib/admin/authz"
	"github.com/authgear/authgear-server/pkg/lib/config"
	"github.com/authgear/authgear-server/pkg/lib/session"
	"github.com/authgear/authgear-server/pkg/lib/uiparam"
	"github.com/authgear/authgear-server/pkg/util/clock"
	"github.com/authgear/authgear-server/pkg/util/httputil"
	"github.com/authgear/authgear-server/pkg/util/intl"
)

type HookSink interface {
	ReceiveBlockingEventNoApply(e *event.Event) (*event.Mutations, error)
}

// BlockingEventService dispatches blocking events.
// It does not depend on database transaction lifecycle, and does not resolve payload.
// The payload must be fully resolved beforehand.
type BlockingEventService struct {
	Context         context.Context
	AppID           config.AppID
	RemoteIP        httputil.RemoteIP
	UserAgentString httputil.UserAgentString
	Logger          Logger
	Clock           clock.Clock
	Localization    *config.LocalizationConfig
	Store           Store
	HookSink        HookSink
}

func (s *BlockingEventService) DispatchEvent(payload event.BlockingPayload) (mutations *event.Mutations, err error) {
	eventContext := s.makeContext(payload)
	var seq int64
	seq, err = s.nextSeq()
	if err != nil {
		return
	}

	e := newBlockingEvent(seq, payload, eventContext)
	mutations, err = s.HookSink.ReceiveBlockingEventNoApply(e)
	if err != nil {
		return
	}

	return
}

func (s *BlockingEventService) nextSeq() (seq int64, err error) {
	seq, err = s.Store.NextSequenceNumber()
	if err != nil {
		return
	}
	return
}

func (s *BlockingEventService) makeContext(payload event.Payload) event.Context {
	userID := session.GetUserID(s.Context)

	if userID == nil {
		uid := payload.UserID()
		if uid != "" {
			userID = &uid
		}
	}

	preferredLanguageTags := intl.GetPreferredLanguageTags(s.Context)
	// Initialize this to an empty slice so that it is always present in the JSON.
	if preferredLanguageTags == nil {
		preferredLanguageTags = []string{}
	}
	resolvedLanguageIdx, _ := intl.Resolve(
		preferredLanguageTags,
		*s.Localization.FallbackLanguage,
		s.Localization.SupportedLanguages,
	)

	resolvedLanguage := ""
	if resolvedLanguageIdx != -1 {
		resolvedLanguage = s.Localization.SupportedLanguages[resolvedLanguageIdx]
	}

	triggeredBy := payload.GetTriggeredBy()

	uiParam := uiparam.GetUIParam(s.Context)
	auditCtx := adminauthz.GetAdminAuthzAudit(s.Context)
	clientID := uiParam.ClientID

	var oauthContext *event.OAuthContext
	if uiParam.State != "" || uiParam.XState != "" {
		oauthContext = &event.OAuthContext{
			State:  uiParam.State,
			XState: uiParam.XState,
		}
	}

	ctx := &event.Context{
		Timestamp:          s.Clock.NowUTC().Unix(),
		UserID:             userID,
		TriggeredBy:        triggeredBy,
		AuditContext:       auditCtx,
		PreferredLanguages: preferredLanguageTags,
		Language:           resolvedLanguage,
		IPAddress:          string(s.RemoteIP),
		UserAgent:          string(s.UserAgentString),
		AppID:              string(s.AppID),
		ClientID:           clientID,
		OAuth:              oauthContext,
	}

	payload.FillContext(ctx)

	return *ctx
}
