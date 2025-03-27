package ioc

import (
	"fmt"
	"regexp"
)

type Config struct {
	Name    string
	Content []string
	Pattern string
}

type IOC struct {
	name    string
	content []string
	regex   *regexp.Regexp
}

var existingIOC = map[string]struct {
	content []string
	pattern string
}{
	"tj-actions/changed-files": {
		content: []string{"SHA:0e58ed8671d6b60d0890c21b07f8835ace038e67"},
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
		name:    name,
		content: predefined.content,
		regex:   regex,
	}, true
}

func NewIOC(config *Config) (*IOC, error) {
	if config.Name != "" && len(config.Content) == 0 && config.Pattern == "" {
		if ioc, exists := GetPredefinedIOC(config.Name); exists {
			return ioc, nil
		}
		return nil, fmt.Errorf("predefined IOC not found: %s", config.Name)
	}

	if config.Pattern == "" && len(config.Content) == 0 {
		return nil, fmt.Errorf("either content or pattern is required for novel IOC")
	}

	var regex *regexp.Regexp
	var err error
	if config.Pattern != "" {
		regex, err = regexp.Compile(config.Pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid regex pattern: %w", err)
		}
	}

	name := config.Name
	if name == "" {
		name = "custom"
	}

	return &IOC{
		name:    name,
		content: config.Content,
		regex:   regex,
	}, nil
}

func (i *IOC) GetName() string {
	return i.name
}

func (i *IOC) GetContent() []string {
	return i.content
}

func (i *IOC) GetRegex() *regexp.Regexp {
	return i.regex
}
