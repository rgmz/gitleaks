package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func FlutterwavePublicKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Detected a Finicity Public Key, potentially exposing public cryptographic operations and integrations.",
		RuleID:      "flutterwave-public-key",
		Regex:       regexp.MustCompile(`FLWPUBK_TEST-(?i)[a-h0-9]{32}-X`),
		Keywords:    []string{"FLWPUBK_TEST"},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("flutterwavePubKey", "FLWPUBK_TEST-"+secrets.NewSecret(utils.Hex("32"))+"-X"),
	}
	return utils.Validate(r, tps, nil)
}

func FlutterwaveSecretKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Identified a Flutterwave Secret Key, risking unauthorized financial transactions and data breaches.",
		RuleID:      "flutterwave-secret-key",
		Regex:       regexp.MustCompile(`FLWSECK_TEST-(?i)[a-h0-9]{32}-X`),
		Keywords:    []string{"FLWSECK_TEST"},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("flutterwavePubKey", "FLWSECK_TEST-"+secrets.NewSecret(utils.Hex("32"))+"-X"),
	}
	return utils.Validate(r, tps, nil)
}

func FlutterwaveEncKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Uncovered a Flutterwave Encryption Key, which may compromise payment processing and sensitive financial information.",
		RuleID:      "flutterwave-encryption-key",
		Regex:       regexp.MustCompile(`FLWSECK_TEST-(?i)[a-h0-9]{12}`),
		Keywords:    []string{"FLWSECK_TEST"},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("flutterwavePubKey", "FLWSECK_TEST-"+secrets.NewSecret(utils.Hex("12"))),
	}
	return utils.Validate(r, tps, nil)
}
