package resources

import (
	"fmt"
	"io/ioutil"
	"path"

	"github.com/spf13/afero"

	"github.com/authgear/authgear-server/pkg/lib/config/configsource"
	libresource "github.com/authgear/authgear-server/pkg/lib/resource"
	"github.com/authgear/authgear-server/pkg/util/resource"
)

type Update struct {
	Path string
	Data []byte
}

const ConfigFileMaxSize = 100 * 1024

func Validate(appID string, appFs resource.Fs, resources *resource.Manager, updates []Update) error {
	// Validate file size.
	for _, f := range updates {
		if len(f.Data) > ConfigFileMaxSize {
			return fmt.Errorf("invalid resource '%s': too large (%v > %v)", f.Path, len(f.Data), ConfigFileMaxSize)
		}
	}

	// Validate valid resource path.
	for _, u := range updates {
		valid := false
		for _, desc := range resources.Registry.Descriptors {
			if !desc.MatchResource(u.Path) {
				continue
			}
			valid = true
			break
		}
		if !valid {
			return fmt.Errorf("invalid resource '%s': unknown resource path", u.Path)
		}
	}

	// Construct new resource manager.
	newResources, _, err := constructResources(resources, appFs, updates)
	if err != nil {
		return err
	}

	// Validate resource FS.
	paths, err := List(newResources)
	if err != nil {
		return err
	}
	resFiles, err := Load(newResources, paths...)
	if err != nil {
		return err
	}
	for _, res := range resFiles {
		var layers []resource.FsFile
		for _, f := range res.FsFiles {
			layers = append(layers, resource.FsFile{
				Path: res.Path,
				Data: f.Data,
				Fs:   f.Fs,
			})
		}

		merged, err := res.Descriptor.Merge(layers, nil)
		if err != nil {
			return fmt.Errorf("invalid resource '%s': %w", res.Path, err)
		}
		_, err = res.Descriptor.Parse(merged)
		if err != nil {
			return fmt.Errorf("invalid resource '%s': %w", res.Path, err)
		}
	}

	// Validate configuration.
	cfg, err := configsource.LoadConfig(newResources)
	if err != nil {
		return err
	}
	if string(cfg.AppConfig.ID) != appID {
		return fmt.Errorf("invalid resource '%s': incorrect app ID", configsource.AuthgearYAML)
	}

	return nil
}

func constructResources(resources *resource.Manager, appFs resource.Fs, updates []Update) (*resource.Manager, resource.Fs, error) {
	newFs := afero.NewMemMapFs()
	paths, err := resource.ListFiles(appFs)
	if err != nil {
		return nil, nil, err
	}
	for _, p := range paths {
		err := func() error {
			f, err := appFs.Open(p)
			if err != nil {
				return err
			}
			defer f.Close()

			data, err := ioutil.ReadAll(f)
			if err != nil {
				return err
			}

			_ = newFs.MkdirAll(path.Dir(p), 0666)
			_ = afero.WriteFile(newFs, p, data, 0666)
			return nil
		}()
		if err != nil {
			return nil, nil, err
		}
	}
	for _, u := range updates {
		if u.Data == nil {
			_ = newFs.Remove(u.Path)
		} else {
			_ = newFs.MkdirAll(path.Dir(u.Path), 0666)
			_ = afero.WriteFile(newFs, u.Path, u.Data, 0666)
		}
	}

	newAppFs := resource.AferoLeveledFs{Fs: newFs, FsLevel: libresource.FsLevelApp}
	var newResFs []resource.Fs
	for _, fs := range resources.Fs {
		if fs.Level() == libresource.FsLevelApp {
			newResFs = append(newResFs, newAppFs)
		} else {
			newResFs = append(newResFs, fs)
		}
	}
	return resource.NewManager(resources.Registry, newResFs), newAppFs, nil
}
