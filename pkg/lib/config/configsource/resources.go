package configsource

import (
	"fmt"
	"os"

	"sigs.k8s.io/yaml"

	"github.com/authgear/authgear-server/pkg/lib/config"
	"github.com/authgear/authgear-server/pkg/util/resource"
)

const (
	AuthgearYAML       = "authgear.yaml"
	AuthgearSecretYAML = "authgear.secrets.yaml"
)

var AppConfig = resource.RegisterResource(resource.SimpleFile{
	Name: AuthgearYAML,
	ParseFn: func(data []byte) (interface{}, error) {
		appConfig, err := config.Parse(data)
		if err != nil {
			return nil, fmt.Errorf("cannot parse app config: %w", err)
		}
		return appConfig, nil
	},
})

var SecretConfig = resource.RegisterResource(SecretConfigResourceType{})

type SecretConfigResourceType struct{}

func (f SecretConfigResourceType) ReadResource(fs resource.Fs) ([]resource.FsFile, error) {
	data, err := resource.ReadFile(fs, AuthgearSecretYAML)
	if os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return []resource.FsFile{{Path: AuthgearSecretYAML, Data: data, Fs: fs}}, nil
}

func (f SecretConfigResourceType) MatchResource(path string) bool {
	return path == AuthgearSecretYAML
}

func (f SecretConfigResourceType) Merge(layers []resource.FsFile, args map[string]interface{}) (*resource.MergedFile, error) {
	var layerConfigs []*config.SecretConfig
	for _, layer := range layers {
		var layerConfig config.SecretConfig
		if err := yaml.Unmarshal(layer.Data, &layerConfig); err != nil {
			return nil, fmt.Errorf("malformed secret config: %w", err)
		}
		layerConfigs = append(layerConfigs, &layerConfig)
	}

	mergedConfig := (&config.SecretConfig{}).Overlay(layerConfigs...)
	mergedYAML, err := yaml.Marshal(mergedConfig)
	if err != nil {
		return nil, err
	}

	return &resource.MergedFile{Data: mergedYAML}, nil
}

func (f SecretConfigResourceType) Parse(merged *resource.MergedFile) (interface{}, error) {
	secretConfig, err := config.ParseSecret(merged.Data)
	if err != nil {
		return nil, fmt.Errorf("cannot parse secret config: %w", err)
	}
	return secretConfig, nil
}
