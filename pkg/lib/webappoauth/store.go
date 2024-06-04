package webappoauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	goredis "github.com/go-redis/redis/v8"

	"github.com/authgear/authgear-server/pkg/lib/config"
	"github.com/authgear/authgear-server/pkg/lib/infra/redis/appredis"
	"github.com/authgear/authgear-server/pkg/util/base32"
	"github.com/authgear/authgear-server/pkg/util/duration"
	"github.com/authgear/authgear-server/pkg/util/rand"
)

type Store struct {
	Context context.Context
	Redis   *appredis.Handle
	AppID   config.AppID
}

func NewStateString() string {
	// Some provider has a hard-limit on the length of the state.
	// Here we use 32 which is observed to be short enough.
	return rand.StringWithAlphabet(32, base32.Alphabet, rand.SecureRand)
}

func (s *Store) GenerateState(state *WebappOAuthState) (stateString string, err error) {
	data, err := json.Marshal(state)
	if err != nil {
		return
	}

	ttl := duration.UserInteraction

	stateString = NewStateString()
	key := stateKey(string(s.AppID), stateString)

	err = s.Redis.WithConn(func(conn *goredis.Conn) error {
		_, err := conn.SetNX(s.Context, key, data, ttl).Result()
		if errors.Is(err, goredis.Nil) {
			err = fmt.Errorf("state string already exist: %w", err)
			return err
		} else if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return
	}

	return
}

func (s *Store) RecoverState(stateString string) (state *WebappOAuthState, err error) {
	key := stateKey(string(s.AppID), stateString)

	var data []byte
	err = s.Redis.WithConn(func(conn *goredis.Conn) error {
		var err error
		data, err = conn.Get(s.Context, key).Bytes()
		if errors.Is(err, goredis.Nil) {
			err = fmt.Errorf("state string not found: %w", err)
			return err
		} else if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return
	}

	var stateStruct WebappOAuthState
	err = json.Unmarshal(data, &stateStruct)
	if err != nil {
		return
	}

	state = &stateStruct
	return
}

func stateKey(appID string, stateString string) string {
	return fmt.Sprintf("app:%s:oauthrelyingparty-state:%s", appID, stateString)
}
