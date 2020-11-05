package resource

import (
	"github.com/authgear/authgear-server/pkg/api/apierrors"
)

var ErrResourceNotFound = apierrors.NotFound.WithReason("ResourceNotFound").
	New("specified resource is not configured")

// Manager is a registry with layered filesystems.
type Manager struct {
	Registry *Registry
	Fs       []Fs
}

func NewManager(registry *Registry, fs []Fs) *Manager {
	return &Manager{Registry: registry, Fs: fs}
}

// Overlay returns a new manaager overlaid with fs.
func (m *Manager) Overlay(fs Fs) *Manager {
	newFs := make([]Fs, len(m.Fs)+1)
	copy(newFs, m.Fs)
	newFs[len(newFs)-1] = fs
	return NewManager(m.Registry, newFs)
}

// Read reads merged file from all FSs of m.
func (m *Manager) Read(desc Descriptor, args map[string]interface{}) (*MergedFile, error) {
	var fsFiles []FsFile
	for _, fs := range m.Fs {
		files, err := desc.ReadResource(fs)
		if err != nil {
			return nil, err
		}
		fsFiles = append(fsFiles, files...)
	}
	if len(fsFiles) == 0 {
		return nil, ErrResourceNotFound
	}

	merged, err := desc.Merge(fsFiles, args)
	if err != nil {
		return nil, err
	}

	return merged, nil
}

// Resolve finds the first descriptor for path.
func (m *Manager) Resolve(path string) (Descriptor, bool) {
	for _, desc := range m.Registry.Descriptors {
		if ok := desc.MatchResource(path); ok {
			return desc, true
		}
	}
	return nil, false
}

func (m *Manager) Filesystems() []Fs {
	return m.Fs
}
