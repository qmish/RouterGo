package config

import (
	"os"
	"strings"
)

func ResolveSecret(value string) string {
	if value == "" {
		return ""
	}
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "env:") {
		return os.Getenv(strings.TrimPrefix(value, "env:"))
	}
	if strings.HasPrefix(value, "file:") {
		path := strings.TrimPrefix(value, "file:")
		data, err := os.ReadFile(path)
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(data))
	}
	return value
}
