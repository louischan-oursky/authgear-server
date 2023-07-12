package workflowconfig

import (
	"github.com/authgear/authgear-server/pkg/api/apierrors"
)

var ErrFlowNotFound = apierrors.NotFound.WithReason("WorkflowConfigFlowNotFound").New("flow not found")
var ErrStepNotFound = apierrors.NotFound.WithReason("WorkflowConfigStepNotFound").New("step not found")

var InvalidIdentificationMethod = apierrors.BadRequest.WithReason("WorkflowConfigInvalidIdentificationMethod")
var InvalidAuthenticationMethod = apierrors.BadRequest.WithReason("WorkflowConfigInvalidAuthenticationMethod")
var InvalidTargetStep = apierrors.InternalError.WithReason("WorkflowConfigInvalidTargetStep")
var InvalidOOBOTPChannel = apierrors.BadRequest.WithReason("WorkflowConfigInvalidOOBOTPChannel")
var InvalidUserProfile = apierrors.BadRequest.WithReason("WorkflowConfigInvalidUserProfile")
