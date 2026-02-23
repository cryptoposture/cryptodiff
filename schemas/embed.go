package schemas

import (
	"embed"
	"fmt"
	"io/fs"
)

//go:embed *.json
var schemaFS embed.FS

func Load(name string) ([]byte, error) {
	b, err := fs.ReadFile(schemaFS, name)
	if err != nil {
		return nil, fmt.Errorf("load schema %q: %w", name, err)
	}
	return b, nil
}
