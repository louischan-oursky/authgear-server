package resource

import (
	"fmt"
	"sigs.k8s.io/yaml"

	"github.com/authgear/authgear-server/pkg/lib/config"
	"github.com/authgear/authgear-server/pkg/lib/config/configsource"
	libresource "github.com/authgear/authgear-server/pkg/lib/resource"
	portalconfig "github.com/authgear/authgear-server/pkg/portal/config"
	"github.com/authgear/authgear-server/pkg/util/resource"
)

type secretConfig struct {
	Config *config.SecretConfig
	Level  resource.FsLevel
}

const (
	ArgMergeForClientRead string = "merge_for_client_read"
)

type SecretConfigResourceType struct {
	originalImpl       configsource.SecretConfigResourceType
	SecretKeyAllowlist portalconfig.SecretKeyAllowlist
}

func (d SecretConfigResourceType) ReadResource(fs resource.Fs) ([]resource.FsFile, error) {
	return d.originalImpl.ReadResource(fs)
}

func (d SecretConfigResourceType) MatchResource(path string) bool {
	return d.originalImpl.MatchResource(path)
}

func (d SecretConfigResourceType) Parse(merged *resource.MergedFile) (interface{}, error) {
	return d.originalImpl.Parse(merged)
}

func (d SecretConfigResourceType) Merge(fsFiles []resource.FsFile, args map[string]interface{}) (*resource.MergedFile, error) {
	clientRead, ok := args[ArgMergeForClientRead].(bool)
	if ok && clientRead {
		return d.mergeForClientRead(fsFiles, args)
	}
	return d.mergeForWrite(fsFiles, args)
}

func (d SecretConfigResourceType) mergeForClientRead(fsFiles []resource.FsFile, args map[string]interface{}) (*resource.MergedFile, error) {
	// We are merging the files for client read purpose.
	//
	// The logic is similar to mergeForWrite, except that we hide the secret item instead of raising error.

	var configs []secretConfig
	for _, fsFile := range fsFiles {
		var cfg config.SecretConfig
		if err := yaml.Unmarshal(fsFile.Data, &cfg); err != nil {
			return nil, fmt.Errorf("malformed secret config: %w", err)
		}
		configs = append(configs, secretConfig{
			Config: &cfg,
			Level:  fsFile.Fs.Level(),
		})
	}

	// Construct the blocklist.
	secretKeyBlockListMap := make(map[config.SecretKey]struct{})
	for _, c := range configs {
		if c.Level != libresource.FsLevelApp {
			for _, secretItem := range c.Config.Secrets {
				secretKeyBlockListMap[secretItem.Key] = struct{}{}
			}
		}
	}

	secretKeyAllowlistMap := make(map[config.SecretKey]struct{})
	for _, key := range d.SecretKeyAllowlist {
		secretKeyAllowlistMap[config.SecretKey(key)] = struct{}{}
	}

	var items []config.SecretItem

	// Hide secrets.
	for _, c := range configs {
		if c.Level == libresource.FsLevelApp {
			for _, secretItem := range c.Config.Secrets {
				// Check if the key is in the blocklist
				_, blocked := secretKeyBlockListMap[secretItem.Key]
				if blocked {
					continue
				}

				// Check if the key is in the non-empty allowlist
				if len(secretKeyAllowlistMap) > 0 {
					_, allowed := secretKeyAllowlistMap[secretItem.Key]
					if !allowed {
						continue
					}
				}

				items = append(items, secretItem)
			}
		}
	}

	mergedConfig := &config.SecretConfig{
		Secrets: items,
	}
	mergedYAML, err := yaml.Marshal(mergedConfig)
	if err != nil {
		return nil, err
	}
	return &resource.MergedFile{Data: mergedYAML}, nil
}

func (d SecretConfigResourceType) mergeForWrite(fsFiles []resource.FsFile, args map[string]interface{}) (*resource.MergedFile, error) {
	// We are merging the files for write purpose.
	//
	// We have a blocklist and a allowlist here.
	//
	// All secret key not appearing in FsLevelApp are in the blocklist.
	// That is, the developer cannot override secret defined in lower FS.
	//
	// We also have a allowlist.
	// If the allowlist is empty, then everything not in the blocklist is allowed.
	// Otherwise, in addition to the blocklist, the secret key must also appear in the allowlist.

	// We first start with unmarshalling the secret config and remember their FS level.

	var configs []secretConfig
	for _, fsFile := range fsFiles {
		var cfg config.SecretConfig
		if err := yaml.Unmarshal(fsFile.Data, &cfg); err != nil {
			return nil, fmt.Errorf("malformed secret config: %w", err)
		}
		configs = append(configs, secretConfig{
			Config: &cfg,
			Level:  fsFile.Fs.Level(),
		})
	}

	// Construct the blocklist.
	secretKeyBlockListMap := make(map[config.SecretKey]struct{})
	for _, c := range configs {
		if c.Level != libresource.FsLevelApp {
			for _, secretItem := range c.Config.Secrets {
				secretKeyBlockListMap[secretItem.Key] = struct{}{}
			}
		}
	}

	secretKeyAllowlistMap := make(map[config.SecretKey]struct{})
	for _, key := range d.SecretKeyAllowlist {
		secretKeyAllowlistMap[config.SecretKey(key)] = struct{}{}
	}

	// Check every secret in the FsLevelAppUpdate is allowed.
	for _, c := range configs {
		if c.Level == libresource.FsLevelApp {
			for _, secretItem := range c.Config.Secrets {
				// Check if the key is in the blocklist
				_, blocked := secretKeyBlockListMap[secretItem.Key]
				if blocked {
					return nil, fmt.Errorf("cannot override secret '%s' defined in lower FS", secretItem.Key)
				}

				// Check if the key is in the non-empty allowlist
				if len(secretKeyAllowlistMap) > 0 {
					_, allowed := secretKeyAllowlistMap[secretItem.Key]
					if !allowed {
						return nil, fmt.Errorf("cannot override secret '%s' not in the allowlist", secretItem.Key)
					}
				}
			}
		}
	}

	// Otherwise we fallback to the original implementation.
	return d.originalImpl.Merge(fsFiles, args)
}
