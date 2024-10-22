package scm

import (
	"fmt"
	"strings"
)

type Provider int

const (
	NoProvider Provider = iota
	GitHubProvider
	GitLabProvider
	// TODO: Add others.
)

func ProviderFromString(s string) (Provider, error) {
	switch strings.ToLower(s) {
	case "", "github":
		return GitHubProvider, nil
	case "gitlab":
		return GitLabProvider, nil
	default:
		return GitHubProvider, fmt.Errorf("invalid scm provider value: %s", s)
	}
}
