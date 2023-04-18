package git

import (
	"bufio"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/gitleaks/go-gitdiff/gitdiff"
	"github.com/rs/zerolog/log"
)

var ErrEncountered bool

// GitLog returns a channel of gitdiff.File objects from the
// git log -p command for the given source.
var quotedOptPattern = regexp.MustCompile(`^(?:"[^"]+"|'[^']+')$`)
func GitLog(source string, logOpts string) (<-chan *gitdiff.File, error) {
	sourceClean := filepath.Clean(source)
	var cmd *exec.Cmd
	if logOpts != "" {
		args := []string{"-C", sourceClean, "log", "-p", "-U0"}

		// Ensure that the user-provided |logOpts| aren't wrapped in quotes.
		// https://github.com/gitleaks/gitleaks/issues/1153
		userArgs := strings.Split(logOpts, " ")
		var quotedOpts []string
		for _, element := range userArgs {
			if quotedOptPattern.MatchString(element) {
				quotedOpts = append(quotedOpts, element)
			}
		}
		if len(quotedOpts) > 0 {
			log.Warn().Msgf("the following `--log-opts` values may not work as expected: %v\n\tsee https://github.com/gitleaks/gitleaks/issues/1153 for more information", quotedOpts)
		}

		args = append(args, userArgs...)
		cmd = exec.Command("git", args...)
	} else {
		cmd = exec.Command("git", "-C", sourceClean, "log", "-p", "-U0",
			"--full-history", "--all")
	}

	log.Debug().Msgf("executing: %s", cmd.String())

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}

	go listenForStdErr(stderr)

	if err := cmd.Start(); err != nil {
		return nil, err
	}
	// HACK: to avoid https://github.com/zricethezav/gitleaks/issues/722
	time.Sleep(50 * time.Millisecond)

	return gitdiff.Parse(cmd, stdout)
}

// GitDiff returns a channel of gitdiff.File objects from
// the git diff command for the given source.
func GitDiff(source string, staged bool) (<-chan *gitdiff.File, error) {
	sourceClean := filepath.Clean(source)
	var cmd *exec.Cmd
	cmd = exec.Command("git", "-C", sourceClean, "diff", "-U0", ".")
	if staged {
		cmd = exec.Command("git", "-C", sourceClean, "diff", "-U0",
			"--staged", ".")
	}
	log.Debug().Msgf("executing: %s", cmd.String())

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}

	go listenForStdErr(stderr)

	if err := cmd.Start(); err != nil {
		return nil, err
	}
	// HACK: to avoid https://github.com/zricethezav/gitleaks/issues/722
	time.Sleep(50 * time.Millisecond)

	return gitdiff.Parse(cmd, stdout)
}

// Fetches the repository's default url.
// TODO: Handle both HTTPS and SSH url.
// var httpPattern = regexp.MustCompile(`(?i)^https?://([a-z0-9_.-]+)/(.+)\.git$`)
var sshPattern = regexp.MustCompile(`(?i)^git@([a-z0-9_.-]+):(.+)\.git$`)

func GetRepoUrl(source string) (*string, error) {
	sourceClean := filepath.Clean(source)
	// TODO: Check for the default remote, don't just assume it's 'origin'.
	cmd := exec.Command("git", "-C", sourceClean, "remote", "get-url", "origin")

	var out strings.Builder
	cmd.Stdout = &out

	err := cmd.Run()
	if err != nil {
		return nil, err
	}

	url := out.String()
	url = strings.TrimSuffix(url, "\n")

	if strings.HasPrefix(url, "git@") {
		match := sshPattern.FindStringSubmatch(url)
		if match != nil {
			domain := match[1]
			path := match[2]

			url = "https://" + domain + "/" + path
		} else {
			return nil, fmt.Errorf("failed to parse domain and path for SSH url")
		}
	} else if strings.HasPrefix(url, "http") {
		url = strings.TrimSuffix(url, ".git")
	} else {
		return nil, fmt.Errorf("expected repository URL to start with 'http' or 'git', not %s", url)
	}

	return &url, nil
}

// listenForStdErr listens for stderr output from git and prints it to stdout
// then exits with exit code 1
func listenForStdErr(stderr io.ReadCloser) {
	scanner := bufio.NewScanner(stderr)
	for scanner.Scan() {
		// if git throws one of the following errors:
		//
		//  exhaustive rename detection was skipped due to too many files.
		//  you may want to set your diff.renameLimit variable to at least
		//  (some large number) and retry the command.
		//
		//	inexact rename detection was skipped due to too many files.
		//  you may want to set your diff.renameLimit variable to at least
		//  (some large number) and retry the command.
		//
		// we skip exiting the program as git log -p/git diff will continue
		// to send data to stdout and finish executing. This next bit of
		// code prevents gitleaks from stopping mid scan if this error is
		// encountered
		if strings.Contains(scanner.Text(),
			"exhaustive rename detection was skipped") ||
			strings.Contains(scanner.Text(),
				"inexact rename detection was skipped") ||
			strings.Contains(scanner.Text(),
				"you may want to set your diff.renameLimit") {
			log.Warn().Msg(scanner.Text())
		} else {
			log.Error().Msgf("[git] %s", scanner.Text())

			// asynchronously set this error flag to true so that we can
			// capture a log message and exit with a non-zero exit code
			// This value should get set before the `git` command exits so it's
			// safe-ish, although I know I know, bad practice.
			ErrEncountered = true
		}
	}
}
