package util

import (
	"fmt"
	"path/filepath"
)

func FieldPath(base string, index int, field string) string {
	return fmt.Sprintf("%s[%d].%s", base, index, field)
}

func SplitPath(path string) (string, string) {
	return filepath.Dir(path), filepath.Base(path)
}
