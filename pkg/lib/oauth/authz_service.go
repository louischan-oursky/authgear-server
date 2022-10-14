package oauth

import (
	"github.com/authgear/authgear-server/pkg/lib/session"
)

type OfflineGrantSessionManager interface {
	List(userID string) ([]session.Session, error)
	Delete(session session.Session) error
}

type AuthorizationService struct {
	Store               AuthorizationStore
	OAuthSessionManager OfflineGrantSessionManager
}

func (s *AuthorizationService) GetByID(id string) (*Authorization, error) {
	return s.Store.GetByID(id)
}

func (s *AuthorizationService) ListByUser(userID string, filters ...AuthorizationFilter) ([]*Authorization, error) {
	as, err := s.Store.ListByUserID(userID)
	if err != nil {
		return nil, err
	}

	filtered := []*Authorization{}
	for _, a := range as {
		keep := true
		for _, f := range filters {
			if !f.Keep(a) {
				keep = false
				break
			}
		}
		if keep {
			filtered = append(filtered, a)
		}
	}

	return filtered, nil
}

func (s *AuthorizationService) Delete(a *Authorization) error {
	sessions, err := s.OAuthSessionManager.List(a.UserID)
	if err != nil {
		return err
	}

	// delete the offline grants that belong to the authorization
	for _, sess := range sessions {
		if offlineGrant, ok := sess.(*OfflineGrant); ok {
			if offlineGrant.AuthorizationID == a.ID {
				err := s.OAuthSessionManager.Delete(sess)
				if err != nil {
					return err
				}
			}
		}
	}

	return s.Store.Delete(a)
}