package access

import (
	"context"
	"encoding/json"
	"fmt"

	goredis "github.com/go-redis/redis/v8"

	"github.com/authgear/authgear-server/pkg/lib/config"
	"github.com/authgear/authgear-server/pkg/lib/infra/redis"
)

const maxEventStreamLength = 10

const eventTypeAccessEvent = "access"

type EventStoreRedis struct {
	Redis *redis.Handle
	AppID config.AppID
}

func (s *EventStoreRedis) AppendEvent(sessionID string, event *Event) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	streamKey := accessEventStreamKey(s.AppID, sessionID)
	args := &goredis.XAddArgs{
		Stream: streamKey,
		ID:     "*",
		Values: map[string]interface{}{
			eventTypeAccessEvent: data,
		},
	}
	if maxEventStreamLength >= 0 {
		args.MaxLenApprox = maxEventStreamLength
	}

	return s.Redis.WithConn(func(conn *goredis.Conn) error {
		ctx := context.Background()
		_, err = conn.XAdd(ctx, args).Result()
		if err != nil {
			return err
		}
		return nil
	})
}

func (s *EventStoreRedis) ResetEventStream(sessionID string) error {
	streamKey := accessEventStreamKey(s.AppID, sessionID)

	return s.Redis.WithConn(func(conn *goredis.Conn) error {
		ctx := context.Background()
		_, err := conn.Del(ctx, streamKey).Result()
		if err != nil {
			return err
		}

		return nil
	})
}

func accessEventStreamKey(appID config.AppID, sessionID string) string {
	return fmt.Sprintf("app:%s:access-events:%s", appID, sessionID)
}
