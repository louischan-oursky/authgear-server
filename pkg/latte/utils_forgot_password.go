package latte

import (
	"errors"

	"github.com/authgear/authgear-server/pkg/api/model"
	"github.com/authgear/authgear-server/pkg/lib/workflow"
)

var ErrNoMatchingLoginIDForForgotPasswordChannel = errors.New("no matching login id for selected forgot password channel")

func selectForgotPasswordLoginID(
	deps *workflow.Dependencies,
	userID string,
	channel ForgotPasswordChannel) (string, error) {
	// FIXME(workflow): retrieve dependency elsewhere
	loginIDs, err := deps.Accounts.ListIdentitiesOfUser(userID)
	if err != nil {
		return "", err
	}

	var targetLoginID *string

	switch channel {
	case ForgotPasswordChannelEmail:
		for _, loginID := range loginIDs {
			if loginID.Type != model.IdentityTypeLoginID {
				continue
			}
			if loginID.LoginID.LoginIDType != model.LoginIDKeyTypeEmail {
				continue
			}
			targetLoginID = &loginID.LoginID.LoginID
			break
		}
	case ForgotPasswordChannelSMS:
		for _, loginID := range loginIDs {
			if loginID.Type != model.IdentityTypeLoginID {
				continue
			}
			if loginID.LoginID.LoginIDType != model.LoginIDKeyTypePhone {
				continue
			}
			targetLoginID = &loginID.LoginID.LoginID
			break
		}
	}

	if targetLoginID != nil {
		return *targetLoginID, nil
	}

	return "", ErrNoMatchingLoginIDForForgotPasswordChannel
}
