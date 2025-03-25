package ioc

import (
	"fmt"
	"regexp"
)

type Config struct {
	Name    string
	Digest  string
	Pattern string
}

type IOC struct {
	name   string
	digest string
	regex  *regexp.Regexp
}

var existingIOC = map[string]struct {
	digest  string
	pattern string
}{
	"tj-actions/changed-files": {
		digest:  "0e58ed8671d6b60d0890c21b07f8835ace038e67",
		pattern: `(?:^|\s+)([A-Za-z0-9+/]{40,}={0,3})`,
	},
}

func GetPredefinedIOC(name string) (*IOC, bool) {
	predefined, exists := existingIOC[name]
	if !exists {
		return nil, false
	}

	regex, err := regexp.Compile(predefined.pattern)
	if err != nil {
		return nil, false
	}

	return &IOC{
		name:   name,
		digest: predefined.digest,
		regex:  regex,
	}, true
}

func NewIOC(config *Config) (*IOC, error) {
	if config.Name != "" && config.Digest == "" && config.Pattern == "" {
		if ioc, exists := GetPredefinedIOC(config.Name); exists {
			return ioc, nil
		}
		return nil, fmt.Errorf("predefined IOC not found: %s", config.Name)
	}

	if config.Pattern == "" {
		return nil, fmt.Errorf("pattern is required for novel IOC")
	}

	regex, err := regexp.Compile(config.Pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid regex pattern: %w", err)
	}

	name := config.Name
	if name == "" {
		name = "custom"
	}

	return &IOC{
		name:   name,
		digest: config.Digest,
		regex:  regex,
	}, nil
}

func (i *IOC) GetName() string {
	return i.name
}

func (i *IOC) GetDigest() string {
	return i.digest
}

func (i *IOC) GetRegex() *regexp.Regexp {
	return i.regex
}
