package resource

import (
	"github.com/spf13/afero"

	"github.com/authgear/authgear-server/pkg/util/resource"
)

const (
	FsLevelBuiltin resource.FsLevel = 1
	FsLevelCustom  resource.FsLevel = 2
	FsLevelApp     resource.FsLevel = 3
)

func NewResourceManager(registry *resource.Registry, builtinResourceDir string, customResourceDir string) *resource.Manager {
	var fs []resource.Fs
	fs = append(fs,
		resource.AferoLeveledFs{
			Fs:      afero.NewBasePathFs(afero.OsFs{}, builtinResourceDir),
			FsLevel: FsLevelBuiltin,
		},
	)
	if customResourceDir != "" {
		fs = append(fs,
			resource.AferoLeveledFs{
				Fs:      afero.NewBasePathFs(afero.OsFs{}, customResourceDir),
				FsLevel: FsLevelCustom,
			},
		)
	}
	return &resource.Manager{
		Registry: registry.Clone(),
		Fs:       fs,
	}
}
