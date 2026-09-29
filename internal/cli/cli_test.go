package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixture = "../../testdata/observations/github.com.json"
const badFixture = "../../testdata/observations/example.com.json"

// run executes the command tree with the given arguments and captures stdout.
func run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), err
}

func TestScanFromObservationText(t *testing.T) {
	out, err := run(t, "scan", "--from-observation", fixture, "--no-color", "--explain-score")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"github.com", "grade", "SCORE EXPLANATION", "hsts"} {
		if !strings.Contains(out, want) {
			t.Errorf("output should contain %q", want)
		}
	}
}

func TestScanFromObservationJSON(t *testing.T) {
	out, err := run(t, "scan", "--from-observation", fixture, "--format", "json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if doc["schema_version"] != float64(1) {
		t.Errorf("schema_version = %v", doc["schema_version"])
	}
}

func TestScanWritesEveryFormatToAFile(t *testing.T) {
	dir := t.TempDir()
	for _, format := range []string{"text", "json", "html", "markdown"} {
		path := filepath.Join(dir, "report."+format)
		out, err := run(t, "scan", "--from-observation", fixture, "--format", format, "--output", path)
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		if !strings.Contains(out, "wrote ") {
			t.Errorf("%s: the command should say where it wrote: %q", format, out)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		if len(b) < 200 {
			t.Errorf("%s: wrote only %d bytes", format, len(b))
		}
		if format == "text" && bytes.Contains(b, []byte("\033[")) {
			t.Error("a report redirected to a file should not carry terminal colour codes")
		}
	}
}

func TestScanRejectsAnUnknownFormat(t *testing.T) {
	if _, err := run(t, "scan", "--from-observation", fixture, "--format", "yaml"); err == nil {
		t.Fatal("an unknown format should be an error")
	}
}

func TestScanNeedsATargetOrAnObservation(t *testing.T) {
	if _, err := run(t, "scan"); err == nil {
		t.Fatal("scan with no target and no observation should be an error")
	}
}

func TestScanRejectsContradictoryScopeFlags(t *testing.T) {
	_, err := run(t, "scan", "--from-observation", fixture, "--headers-only", "--tls-only")
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("err = %v", err)
	}
}

func TestScanRejectsAnUnknownRemediationServer(t *testing.T) {
	if _, err := run(t, "scan", "--from-observation", fixture, "--remediate-for", "iis"); err == nil {
		t.Fatal("an unsupported server should be an error")
	}
}

func TestScanRejectsAMissingObservation(t *testing.T) {
	if _, err := run(t, "scan", "--from-observation", filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("a missing observation file should be an error")
	}
}

func TestScanRejectsAForeignObservationSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "obs.json")
	if err := os.WriteFile(path, []byte(`{"schema_version": 99}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := run(t, "scan", "--from-observation", path)
	if err == nil || !strings.Contains(err.Error(), "schema_version") {
		t.Fatalf("err = %v", err)
	}
}

func TestFailUnderGatesOnTheGrade(t *testing.T) {
	// github.com grades well, so a C threshold passes and an A+ one does not.
	if _, err := run(t, "scan", "--from-observation", fixture, "--fail-under", "C", "--format", "json"); err != nil {
		t.Errorf("a C threshold should pass: %v", err)
	}
	_, err := run(t, "scan", "--from-observation", fixture, "--fail-under", "A+", "--format", "json")
	if err == nil {
		t.Fatal("an A+ threshold should not pass")
	}
	if _, ok := err.(thresholdError); !ok {
		t.Errorf("a threshold failure should be distinguishable from a tool error, got %T", err)
	}
}

func TestFailUnderRejectsAnUnknownGrade(t *testing.T) {
	_, err := run(t, "scan", "--from-observation", fixture, "--fail-under", "B-", "--format", "json")
	if err == nil || !strings.Contains(err.Error(), "unknown grade") {
		t.Fatalf("err = %v", err)
	}
}

func TestSaveObservationRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "saved.json")
	if _, err := run(t, "scan", "--from-observation", fixture, "--save-observation", path, "--format", "json"); err != nil {
		t.Fatal(err)
	}
	obs, err := LoadObservation(path)
	if err != nil {
		t.Fatal(err)
	}
	if obs.Host != "github.com" {
		t.Errorf("host = %s", obs.Host)
	}
}

func TestIncludeObservationEmbedsTheEvidence(t *testing.T) {
	out, err := run(t, "scan", "--from-observation", fixture, "--format", "json", "--include-observation")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if _, ok := doc["observation"]; !ok {
		t.Error("the raw evidence should be embedded")
	}
}

func TestDiffCommand(t *testing.T) {
	dir := t.TempDir()
	before := filepath.Join(dir, "before.json")
	after := filepath.Join(dir, "after.json")

	if _, err := run(t, "scan", "--from-observation", badFixture, "--format", "json", "--output", before); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, "scan", "--from-observation", fixture, "--format", "json", "--output", after); err != nil {
		t.Fatal(err)
	}

	out, err := run(t, "diff", before, after, "--no-color")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "FIXED") {
		t.Errorf("a much better report should show fixes:\n%s", out)
	}

	// The other direction is a regression, which the gate should catch.
	_, err = run(t, "diff", after, before, "--fail-on-regression", "--no-color")
	if err == nil {
		t.Fatal("a regression should fail the gate")
	}
	if _, ok := err.(thresholdError); !ok {
		t.Errorf("a regression should use the threshold exit code, got %T", err)
	}
}

func TestDiffFormats(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.json")
	b := filepath.Join(dir, "b.json")
	_, _ = run(t, "scan", "--from-observation", badFixture, "--format", "json", "--output", a)
	_, _ = run(t, "scan", "--from-observation", fixture, "--format", "json", "--output", b)

	md, err := run(t, "diff", a, b, "--format", "markdown")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(md, "## httpsec diff") {
		t.Error("markdown diff is wrong")
	}

	js, err := run(t, "diff", a, b, "--format", "json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(js), &doc); err != nil {
		t.Fatalf("json diff is not valid JSON: %v", err)
	}

	if _, err := run(t, "diff", a, b, "--format", "yaml"); err == nil {
		t.Error("an unknown format should be an error")
	}
}

func TestRemediateFromObservation(t *testing.T) {
	for _, server := range []string{"nginx", "apache", "caddy", "cdn"} {
		out, err := run(t, "remediate", "--from-observation", badFixture, "--server", server)
		if err != nil {
			t.Fatalf("%s: %v", server, err)
		}
		if len(out) < 500 {
			t.Errorf("%s: output is only %d bytes", server, len(out))
		}
		if !strings.Contains(out, "httpsec remediation for") {
			t.Errorf("%s: missing the header", server)
		}
	}
}

func TestRemediateAllAndByFinding(t *testing.T) {
	all, err := run(t, "remediate", "--all", "--server", "nginx")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(all, "Strict-Transport-Security") {
		t.Error("--all should cover the whole catalogue")
	}

	one, err := run(t, "remediate", "--finding", "hsts.missing", "--server", "caddy")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(one, "header Strict-Transport-Security") {
		t.Errorf("= %s", one)
	}
	if len(one) >= len(all) {
		t.Error("one finding should produce less output than the whole catalogue")
	}

	if _, err := run(t, "remediate", "--finding", "not.a.finding"); err == nil {
		t.Error("an unknown finding ID should be an error")
	}
	if _, err := run(t, "remediate", "--finding", "hsts.ok"); err == nil {
		t.Error("a passing control has nothing to remediate")
	}
}

func TestRemediateRejectsAnUnknownServer(t *testing.T) {
	if _, err := run(t, "remediate", "--all", "--server", "iis"); err == nil {
		t.Fatal("an unsupported server should be an error")
	}
}

func TestRemediateNeedsASource(t *testing.T) {
	if _, err := run(t, "remediate", "--server", "nginx"); err == nil {
		t.Fatal("remediate with no source should be an error")
	}
}

func TestRemediateFromReport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.json")
	if _, err := run(t, "scan", "--from-observation", badFixture, "--format", "json", "--output", path); err != nil {
		t.Fatal(err)
	}
	out, err := run(t, "remediate", "--report", path, "--server", "nginx")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "add_header") {
		t.Error("the nginx snippets should be present")
	}
}

func TestRemediateToFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fix.conf")
	out, err := run(t, "remediate", "--all", "--server", "nginx", "--output", path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "wrote ") {
		t.Errorf("= %q", out)
	}
	if b, err := os.ReadFile(path); err != nil || len(b) == 0 {
		t.Errorf("the file should have content: %v", err)
	}
}

func TestRubricCommand(t *testing.T) {
	out, err := run(t, "rubric")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"control", "weight", "grade bands", "severity penalty"} {
		if !strings.Contains(out, want) {
			t.Errorf("rubric output should contain %q", want)
		}
	}
	withCaps, err := run(t, "rubric", "--caps")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(withCaps, "tls.version.tls10") {
		t.Error("--caps should list the capping findings")
	}
}

func TestVersionCommand(t *testing.T) {
	out, err := run(t, "version")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, "httpsec ") {
		t.Errorf("= %q", out)
	}
}

func TestBatchReadsTargetsAndReportsErrors(t *testing.T) {
	dir := t.TempDir()
	list := filepath.Join(dir, "targets.txt")
	// 127.0.0.1:1 is not listening, so both targets fail fast and the test
	// makes no outbound connection.
	content := "# a comment\n\n127.0.0.1:1\n127.0.0.1:1\n"
	if err := os.WriteFile(list, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := run(t, "batch", list, "--timeout", "500ms", "--budget", "3s", "--concurrency", "2", "--headers-only")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "1 targets") {
		t.Errorf("duplicates should be collapsed:\n%s", out)
	}
}

func TestBatchRejectsAnEmptyList(t *testing.T) {
	list := filepath.Join(t.TempDir(), "empty.txt")
	if err := os.WriteFile(list, []byte("# nothing here\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, "batch", list); err == nil {
		t.Fatal("an empty target list should be an error")
	}
	if _, err := run(t, "batch", filepath.Join(t.TempDir(), "missing.txt")); err == nil {
		t.Fatal("a missing target list should be an error")
	}
}

func TestReadTargets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.txt")
	if err := os.WriteFile(path, []byte("a.test\n\n# comment\nb.test\na.test\n  c.test  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readTargets(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a.test", "b.test", "c.test"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("= %v, want %v", got, want)
	}
}

func TestLoadRoots(t *testing.T) {
	if pool, err := loadRoots(""); pool != nil || err != nil {
		t.Errorf("an empty path means the system store: %v %v", pool, err)
	}
	if _, err := loadRoots(filepath.Join(t.TempDir(), "absent.pem")); err == nil {
		t.Error("a missing bundle should be an error")
	}
	bad := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(bad, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRoots(bad); err == nil {
		t.Error("a bundle with no certificates should be an error")
	}
	if pool, err := loadRoots("../../testdata/certs/ca.cert.pem"); err != nil || pool == nil {
		t.Errorf("the test CA should load: %v", err)
	}
}

func TestExecuteWithMapsErrorsToExitCodes(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"success", []string{"version"}, ExitOK},
		{"tool error", []string{"scan"}, ExitError},
		{"threshold", []string{"scan", "--from-observation", badFixture, "--format", "json", "--fail-under", "A+"}, ExitThreshold},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := NewRootCommand()
			root.SetOut(new(bytes.Buffer))
			root.SetErr(new(bytes.Buffer))
			root.SetArgs(c.args)
			if got := ExecuteWith(root); got != c.want {
				t.Errorf("exit code = %d, want %d", got, c.want)
			}
		})
	}
}

func TestWrapText(t *testing.T) {
	got := wrapText("one two three four five", 9)
	if !strings.Contains(got, "\n") {
		t.Errorf("= %q, want wrapped", got)
	}
	for _, line := range strings.Split(got, "\n") {
		if len(line) > 12 {
			t.Errorf("line %q is too long", line)
		}
	}
}

func TestRootCommandHasEverySubcommand(t *testing.T) {
	root := NewRootCommand()
	want := map[string]bool{"scan": false, "batch": false, "diff": false, "remediate": false, "rubric": false, "version": false}
	for _, c := range root.Commands() {
		if _, ok := want[c.Name()]; ok {
			want[c.Name()] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("command %s is missing", name)
		}
	}
	if root.Use != "httpsec" {
		t.Errorf("root command name = %q", root.Use)
	}
}
