package config

import (
	"fmt"
	"strings"

	ahocorasick "github.com/BobuSumisu/aho-corasick"
	"golang.org/x/exp/maps"

	"github.com/zricethezav/gitleaks/v8/regexp"
)

type AllowlistMatchCondition int

const (
	AllowlistMatchOr AllowlistMatchCondition = iota
	AllowlistMatchAnd
)

func (a AllowlistMatchCondition) String() string {
	return [...]string{
		"OR",
		"AND",
	}[a]
}

// Allowlist allows a rule to be ignored for specific
// regexes, paths, and/or commits
type Allowlist struct {
	// Short human readable description of the allowlist.
	Description string

	// MatchCondition determines whether all criteria must match. Defaults to "OR".
	MatchCondition AllowlistMatchCondition

	// Commits is a slice of commit SHAs that are allowed to be ignored.
	Commits []string

	// Paths is a slice of path regular expressions that are allowed to be ignored.
	Paths []*regexp.Regexp

	// Regexes is slice of content regular expressions that are allowed to be ignored.
	Regexes []*regexp.Regexp

	// Can be `match` or `line`.
	//
	// If `match` the _Regexes_ will be tested against the match of the _Rule.Regex_.
	//
	// If `line` the _Regexes_ will be tested against the entire line.
	//
	// If RegexTarget is empty, it will be tested against the found secret.
	RegexTarget string

	// StopWords is a slice of stop words that are allowed to be ignored.
	// This targets the _secret_, not the content of the regex match like the
	// Regexes slice.
	StopWords []string

	// commitMap is a normalized version of Commits, used for efficiency purposes.
	commitMap    map[string]struct{}
	regexPat     *regexp.Regexp
	pathPat      *regexp.Regexp
	stopwordTrie *ahocorasick.Trie
}

// CommitAllowed returns true if the commit is allowed to be ignored.
func (a *Allowlist) CommitAllowed(c string) (bool, string) {
	if c == "" {
		return false, ""
	}
	if _, ok := a.commitMap[strings.ToLower(c)]; ok {
		return true, ""
	}
	return false, ""
}

// PathAllowed returns true if the path is allowed to be ignored.
func (a *Allowlist) PathAllowed(path string) bool {
	if a.pathPat == nil {
		return false
	}
	return a.pathPat.MatchString(path)
}

// RegexAllowed returns true if the regex is allowed to be ignored.
func (a *Allowlist) RegexAllowed(secret string) bool {
	if a.regexPat == nil {
		return false
	}
	return a.regexPat.MatchString(secret)
}

func (a *Allowlist) ContainsStopWord(s string) (bool, string) {
	if s == "" {
		return false, ""
	}

	//if m := a.stopwordTrie.MatchFirstString(s); m != nil {
	//	return true, m.MatchString()
	//}
	return false, ""
}

func (a *Allowlist) Validate() error {
	// Disallow empty allowlists.
	if len(a.Commits) == 0 &&
		len(a.Paths) == 0 &&
		len(a.Regexes) == 0 &&
		len(a.StopWords) == 0 {
		return fmt.Errorf("[[rules.allowlists]] must contain at least one check for: commits, paths, regexes, or stopwords")
	}

	// Deduplicate commits and stopwords.
	if len(a.Commits) > 0 {
		uniqueCommits := make(map[string]struct{})
		for _, commit := range a.Commits {
			// Commits are case-insensitive.
			uniqueCommits[strings.TrimSpace(strings.ToLower(commit))] = struct{}{}
		}

		//a.Commits = maps.Keys(uniqueCommits)
		a.commitMap = uniqueCommits
	}

	if len(a.Paths) > 0 {
		var sb strings.Builder
		sb.WriteString("(?:")
		for i, path := range a.Paths {
			sb.WriteString(path.String())
			if i != len(a.Paths)-1 {
				sb.WriteString("|")
			}
		}
		sb.WriteString(")")
		a.pathPat = regexp.MustCompile(sb.String())
	}

	if len(a.Regexes) > 0 {
		var sb strings.Builder
		sb.WriteString("(?:")
		for i, regex := range a.Regexes {
			sb.WriteString(regex.String())
			if i != len(a.Regexes)-1 {
				sb.WriteString("|")
			}
		}
		sb.WriteString(")")
		a.regexPat = regexp.MustCompile(sb.String())
	}

	if len(a.StopWords) > 0 {
		uniqueStopwords := make(map[string]struct{})
		for _, stopWord := range a.StopWords {
			uniqueStopwords[stopWord] = struct{}{}
		}

		values := maps.Keys(uniqueStopwords)
		a.StopWords = values
		a.stopwordTrie = ahocorasick.NewTrieBuilder().AddStrings(values).Build()
	}

	return nil
}
