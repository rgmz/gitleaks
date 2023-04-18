package report

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteJSON(t *testing.T) {
	tests := []struct {
		findings       []Finding
		testReportName string
		expected       string
		wantEmpty      bool
	}{
		{
			testReportName: "simple",
			expected:       filepath.Join(expectPath, "report", "json_simple.json"),
			findings: []Finding{
				{

					Description: "",
					RuleID:      "test-rule",
					Match:       "line containing secret",
					Secret:      "a secret",
					StartLine:   1,
					EndLine:     2,
					StartColumn: 1,
					EndColumn:   2,
					Message:     "opps",
					File:        "auth.py",
					SymlinkFile: "",
					Commit:      "0000000000000000",
					Author:      "John Doe",
					Email:       "johndoe@gmail.com",
					Date:        "10-19-2003",
					Url:         "https://github.com/gitleaks/gitleaks/blob/0000000000000000/auth.py",
					Tags:        []string{},
				},
			}},
		{
			testReportName: "nourl",
			expected:       filepath.Join(expectPath, "report", "json_nourl.json"),
			findings: []Finding{
				{

					Description: "",
					RuleID:      "test-rule",
					Match:       "line containing secret",
					Secret:      "a secret",
					StartLine:   1,
					EndLine:     2,
					StartColumn: 1,
					EndColumn:   2,
					Message:     "opps",
					File:        "auth.py",
					SymlinkFile: "",
					Commit:      "0000000000000000",
					Author:      "John Doe",
					Email:       "johndoe@gmail.com",
					Date:        "10-19-2003",
					Tags:        []string{},
				},
			}},
		{

			testReportName: "empty",
			expected:       filepath.Join(expectPath, "report", "empty.json"),
			findings:       []Finding{}},
	}

	for _, test := range tests {
		tmpfile, err := os.Create(filepath.Join(t.TempDir(), test.testReportName+".json"))
		if err != nil {
			t.Error(err)
		}
		err = writeJson(test.findings, tmpfile)
		if err != nil {
			t.Error(err)
		}
		got, err := os.ReadFile(tmpfile.Name())
		if err != nil {
			t.Error(err)
		}
		if test.wantEmpty {
			if len(got) > 0 {
				t.Errorf("Expected empty file, got %s", got)
			}
			continue
		}
		want, err := os.ReadFile(test.expected)
		if err != nil {
			t.Error(err)
		}

		if !bytes.Equal(got, want) {
			err = os.WriteFile(strings.Replace(test.expected, ".json", ".got.json", 1), got, 0644)
			if err != nil {
				t.Error(err)
			}
			t.Errorf("got %s, want %s", string(got), string(want))
		}
	}
}
