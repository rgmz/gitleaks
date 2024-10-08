package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func GitHubPat() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Uncovered a GitHub Personal Access Token, potentially leading to unauthorized repository access and sensitive content exposure.",
		RuleID:      "github-pat",
		Regex:       regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`),
		Entropy:     3,
		Keywords:    []string{"ghp_"},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("github", "ghp_"+secrets.NewSecret(utils.AlphaNumeric("36"))),
	}
	fps := []string{
		"ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	}
	return utils.Validate(r, tps, fps)
}

func GitHubFineGrainedPat() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Found a GitHub Fine-Grained Personal Access Token, risking unauthorized repository access and code manipulation.",
		RuleID:      "github-fine-grained-pat",
		Regex:       regexp.MustCompile(`github_pat_\w{82}`),
		Entropy:     3,
		Keywords:    []string{"github_pat_"},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("github", "github_pat_"+secrets.NewSecret(utils.AlphaNumeric("82"))),
	}
	fps := []string{
		"github_pat_xxxxxxxxxxxxxxxxxxxxxx_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	}
	return utils.Validate(r, tps, fps)
}

func GitHubOauth() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discovered a GitHub OAuth Access Token, posing a risk of compromised GitHub account integrations and data leaks.",
		RuleID:      "github-oauth",
		Regex:       regexp.MustCompile(`gho_[0-9a-zA-Z]{36}`),
		Entropy:     3,
		Keywords:    []string{"gho_"},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("github", "gho_"+secrets.NewSecret(utils.AlphaNumeric("36"))),
	}
	fps := []string{
		"gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	}
	return utils.Validate(r, tps, fps)
}

func GitHubApp() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Identified a GitHub App Token, which may compromise GitHub application integrations and source code security.",
		RuleID:      "github-app-token",
		Regex:       regexp.MustCompile(`(?:ghu|ghs)_[0-9a-zA-Z]{36}`),
		Entropy:     3,
		Keywords:    []string{"ghu_", "ghs_"},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("github", "ghu_"+secrets.NewSecret(utils.AlphaNumeric("36"))),
		utils.GenerateSampleSecret("github", "ghs_"+secrets.NewSecret(utils.AlphaNumeric("36"))),
	}
	fps := []string{
		"ghu_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"ghs_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	}
	return utils.Validate(r, tps, fps)
}

func GitHubRefresh() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Detected a GitHub Refresh Token, which could allow prolonged unauthorized access to GitHub services.",
		RuleID:      "github-refresh-token",
		Regex:       regexp.MustCompile(`ghr_[0-9a-zA-Z]{36}`),
		Entropy:     3,
		Keywords:    []string{"ghr_"},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("github", "ghr_"+secrets.NewSecret(utils.AlphaNumeric("36"))),
	}
	fps := []string{
		"ghr_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	}
	return utils.Validate(r, tps, fps)
}
