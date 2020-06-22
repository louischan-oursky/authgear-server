package task

import (
	"context"

	"github.com/sirupsen/logrus"

	"github.com/skygeario/skygear-server/pkg/auth/task/spec"
	"github.com/skygeario/skygear-server/pkg/core/phone"
	"github.com/skygeario/skygear-server/pkg/deps"
	"github.com/skygeario/skygear-server/pkg/log"
	"github.com/skygeario/skygear-server/pkg/mail"
	"github.com/skygeario/skygear-server/pkg/sms"
	"github.com/skygeario/skygear-server/pkg/task"
)

func AttachSendMessagesTask(
	registry task.Registry,
	p *deps.RootProvider,
) {
	registry.Register(spec.SendMessagesTaskName, p.Task(newSendMessagesTask))
}

type SendMessagesLogger struct{ *log.Logger }

func NewSendMessagesLogger(lf *log.Factory) SendMessagesLogger {
	return SendMessagesLogger{lf.New("send_messages")}
}

type SendMessagesTask struct {
	EmailSender mail.Sender
	SMSClient   sms.Client
	Logger      SendMessagesLogger
}

func (t *SendMessagesTask) Run(ctx context.Context, param interface{}) (err error) {
	taskParam := param.(spec.SendMessagesTaskParam)

	for _, emailMessage := range taskParam.EmailMessages {
		err := t.EmailSender.Send(emailMessage)
		if err != nil {
			t.Logger.WithError(err).WithFields(logrus.Fields{
				"email": mail.MaskAddress(emailMessage.Recipient),
			}).Error("failed to send email")
		}
	}

	for _, smsMessage := range taskParam.SMSMessages {
		err := t.SMSClient.Send(smsMessage)
		if err != nil {
			t.Logger.WithError(err).WithFields(logrus.Fields{
				"phone": phone.Mask(smsMessage.To),
			}).Error("failed to send SMS")
		}
	}

	return
}
