package source

import (
	"context"
	"fmt"
	"github.com/skygeario/skygear-server/pkg/auth/config"
	"github.com/skygeario/skygear-server/pkg/httputil"
	"io/ioutil"
	"net/http"
)

type LocalFile struct {
	serverConfig *config.ServerConfig
	config       *config.Config
}

func NewLocalFile(cfg *config.ServerConfig) *LocalFile {
	return &LocalFile{
		serverConfig: cfg,
	}
}

func (s *LocalFile) Open() error {
	appConfigYAML, err := ioutil.ReadFile(s.serverConfig.ConfigSource.AppConfigPath)
	if err != nil {
		return fmt.Errorf("cannot read app config file: %w", err)
	}
	appConfig, err := config.Parse(appConfigYAML)
	if err != nil {
		return fmt.Errorf("cannot parse app config: %w", err)
	}

	secretConfigYAML, err := ioutil.ReadFile(s.serverConfig.ConfigSource.SecretConfigPath)
	if err != nil {
		return fmt.Errorf("cannot read secret config file: %w", err)
	}
	secretConfig, err := config.ParseSecret(secretConfigYAML)
	if err != nil {
		return fmt.Errorf("cannot parse secret config: %w", err)
	}

	if err = secretConfig.Validate(appConfig); err != nil {
		return fmt.Errorf("invalid secret config: %w", err)
	}

	s.config = &config.Config{
		AppConfig:    appConfig,
		SecretConfig: secretConfig,
	}
	return nil
}

func (s *LocalFile) Close() error {
	return nil
}

func (s *LocalFile) ProvideConfig(ctx context.Context, r *http.Request) (*config.Config, error) {
	if s.serverConfig.DevMode {
		// Accept all hosts under development mode
		return s.config, nil
	}

	host := httputil.GetHost(r, s.serverConfig.TrustProxy)
	for _, h := range s.config.AppConfig.HTTP.Hosts {
		if h == host {
			return s.config, nil
		}
	}
	// TODO(logging): log actual/expected host values at DEBUG level
	return nil, fmt.Errorf("request host is not valid: %w", ErrAppNotFound)
}
