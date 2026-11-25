package sync

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
)

// LoadState reads the set of hostnames installed by sync.
func LoadState(path string) (map[string]bool, error) {
	m := map[string]bool{}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	var list []string
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, err
	}
	for _, h := range list {
		m[h] = true
	}
	return m, nil
}

// SaveState writes the set atomically.
func SaveState(path string, m map[string]bool) error {
	list := make([]string, 0, len(m))
	for h := range m {
		list = append(list, h)
	}
	sort.Strings(list)
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
