package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/zricethezav/gitleaks/v8/cmd/scm"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

func init() {
	rootCmd.AddCommand(gitCmd)
	gitCmd.Flags().String("scm", "github", "the SCM platform used to generate links (github, gitlab)")
	gitCmd.Flags().Bool("staged", false, "scan staged commits (good for pre-commit)")
	gitCmd.Flags().Bool("pre-commit", false, "scan using git diff")
	gitCmd.Flags().String("log-opts", "", "git log options")
}

var gitCmd = &cobra.Command{
	Use:   "git [flags] [repo]",
	Short: "scan git repositories for secrets",
	Args:  cobra.MaximumNArgs(1),
	Run:   runGit,
}

func runGit(cmd *cobra.Command, args []string) {
	var (
		findings []report.Finding
		err      error
	)

	// grab source
	source := "."
	if len(args) == 1 {
		source = args[0]
		if source == "" {
			source = "."
		}
	}

	initConfig(source)

	// setup config (aka, the thing that defines rules)
	cfg := Config(cmd)

	// start timer
	start := time.Now()

	// grab source
	detector := Detector(cmd, cfg, source)
	if remoteUrl, err := getOriginUrl(source); err != nil {
		log.Fatal().Err(err).Msg("failed to get origin url")
	} else {
		detector.RepositoryUrl = remoteUrl
	}

	// set exit code
	exitCode, err := cmd.Flags().GetInt("exit-code")
	if err != nil {
		log.Fatal().Err(err).Msg("could not get exit code")
	}

	var (
		gitCmd      *sources.GitCmd
		scmProvider scm.Provider
		logOpts     string
		preCommit   bool
		staged      bool
	)
	if scmProviderStr, err := cmd.Flags().GetString("scm"); err != nil {
		log.Fatal().Err(err).Msg("could not call GetString() for scm")
	} else {
		scmProvider, err = scm.ProviderFromString(scmProviderStr)
	}
	logOpts, err = cmd.Flags().GetString("log-opts")
	if err != nil {
		log.Fatal().Err(err).Msg("could not call GetString() for log-opts")
	}
	staged, err = cmd.Flags().GetBool("staged")
	if err != nil {
		log.Fatal().Err(err).Msg("could not call GetBool() for staged")
	}
	preCommit, err = cmd.Flags().GetBool("pre-commit")
	if err != nil {
		log.Fatal().Err(err).Msg("could not call GetBool() for pre-commit")
	}

	if preCommit || staged {
		gitCmd, err = sources.NewGitDiffCmd(source, staged)
		if err != nil {
			log.Fatal().Err(err).Msg("could not create Git diff cmd")
		}
	} else {
		gitCmd, err = sources.NewGitLogCmd(source, logOpts)
		if err != nil {
			log.Fatal().Err(err).Msg("could not create Git log cmd")
		}
	}

	findings, err = detector.DetectGit(gitCmd, scmProvider)
	if err != nil {
		// don't exit on error, just log it
		log.Error().Err(err).Msg("failed to scan Git repository")
	}

	findingSummaryAndExit(findings, cmd, cfg, exitCode, start, err)
}

var sshUrlpat = regexp.MustCompile(`^git@([a-zA-Z0-9.-]+):([\w/.-]+?)(?:\.git)?$`)

func getOriginUrl(source string) (string, error) {
	cmd := exec.Command("git", "ls-remote", "--quiet", "--get-url", "origin")
	if source != "." {
		cmd.Dir = source
	}

	stdout, err := cmd.Output()
	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			return "", fmt.Errorf("command failed (%d): %w, stderr: %s", exitError.ExitCode(), err, string(bytes.TrimSpace(exitError.Stderr)))
		}
		return "", err
	}

	remoteUrl := string(bytes.TrimSpace(stdout))
	if matches := sshUrlpat.FindAllStringSubmatch(remoteUrl, 1); matches != nil {
		host := matches[0][1]
		repo := strings.TrimSuffix(matches[0][2], ".git")
		remoteUrl = fmt.Sprintf("https://%s/%s", host, repo)
	}
	return remoteUrl, nil
}
