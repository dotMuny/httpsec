package analyze_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/dotMuny/httpsec/internal/analyze"
	"github.com/dotMuny/httpsec/internal/finding"
	"github.com/dotMuny/httpsec/internal/probe"
	"github.com/dotMuny/httpsec/internal/score"
)

const (
	fixtureDir   = "../../testdata/observations"
	expectations = "../../testdata/expectations.json"
)

// expectation is the hand-reviewed result for one fixture.
type expectation struct {
	Host     string   `json:"host"`
	Grade    string   `json:"grade"`
	Score    int      `json:"score"`
	Problems []string `json:"problems"`
	Caps     []string `json:"caps,omitempty"`
}

func loadFixture(t *testing.T, path string) *probe.Observation {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var obs probe.Observation
	if err := json.Unmarshal(b, &obs); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	if obs.SchemaVersion != probe.ObservationSchemaVersion {
		t.Fatalf("%s: observation schema %d, this build reads %d", path, obs.SchemaVersion, probe.ObservationSchemaVersion)
	}
	return &obs
}

// analyseFixture runs the analysis at the moment the fixture was captured.
// Pinning the clock is what makes certificate-expiry findings reproducible a
// year after the recording was made.
func analyseFixture(obs *probe.Observation) (analyze.Result, score.Score) {
	now := obs.StartedAt
	if now.IsZero() {
		now = time.Now()
	}
	res := analyze.Run(obs, now)
	return res, score.Compute(score.Default(), res.Findings)
}

func fixturePaths(t *testing.T) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(fixtureDir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) < 10 {
		t.Fatalf("found %d fixtures; the corpus is meant to cover a dozen postures", len(paths))
	}
	sort.Strings(paths)
	return paths
}

// TestFixturesMatchExpectations is the reproducibility guarantee: the whole
// analysis runs from recorded evidence, with no network, and has to agree
// with a file that was reviewed by hand.
//
// Regenerate after a deliberate change, then read the diff:
//
//	HTTPSEC_UPDATE_GOLDEN=1 go test ./internal/analyze
func TestFixturesMatchExpectations(t *testing.T) {
	got := map[string]expectation{}

	for _, path := range fixturePaths(t) {
		obs := loadFixture(t, path)
		res, sc := analyseFixture(obs)

		e := expectation{Host: obs.Host, Grade: sc.Grade, Score: sc.Score}
		for _, f := range finding.Problems(res.Findings) {
			id := f.ID
			if f.Subject != "" {
				id += "|" + f.Subject
			}
			e.Problems = append(e.Problems, id)
		}
		sort.Strings(e.Problems)
		for _, c := range sc.Caps {
			e.Caps = append(e.Caps, c.Finding)
		}
		sort.Strings(e.Caps)
		got[filepath.Base(path)] = e
	}

	if os.Getenv("HTTPSEC_UPDATE_GOLDEN") != "" {
		b, err := json.MarshalIndent(got, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(expectations, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Log("expectations updated; review the diff before committing it")
		return
	}

	raw, err := os.ReadFile(expectations)
	if err != nil {
		t.Fatalf("cannot read %s: %v\nRegenerate with HTTPSEC_UPDATE_GOLDEN=1 go test ./internal/analyze", expectations, err)
	}
	var want map[string]expectation
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}

	for name, w := range want {
		g, ok := got[name]
		if !ok {
			t.Errorf("fixture %s is in the expectations but not on disk", name)
			continue
		}
		if g.Grade != w.Grade || g.Score != w.Score {
			t.Errorf("%s: grade/score = %s/%d, want %s/%d", name, g.Grade, g.Score, w.Grade, w.Score)
		}
		for _, missing := range difference(w.Problems, g.Problems) {
			t.Errorf("%s: expected problem %s is no longer reported", name, missing)
		}
		for _, extra := range difference(g.Problems, w.Problems) {
			t.Errorf("%s: unexpected new problem %s", name, extra)
		}
		if strings.Join(g.Caps, ",") != strings.Join(w.Caps, ",") {
			t.Errorf("%s: caps = %v, want %v", name, g.Caps, w.Caps)
		}
	}
	for name := range got {
		if _, ok := want[name]; !ok {
			t.Errorf("fixture %s has no expectations; regenerate and review them", name)
		}
	}
}

func difference(a, b []string) []string {
	inB := map[string]bool{}
	for _, v := range b {
		inB[v] = true
	}
	var out []string
	for _, v := range a {
		if !inB[v] {
			out = append(out, v)
		}
	}
	return out
}

// TestAnalysisIsDeterministic guards the promise that two runs over the same
// evidence produce identical reports.
func TestAnalysisIsDeterministic(t *testing.T) {
	for _, path := range fixturePaths(t) {
		obs := loadFixture(t, path)
		first, _ := analyseFixture(obs)
		second, _ := analyseFixture(obs)

		if len(first.Findings) != len(second.Findings) {
			t.Fatalf("%s: finding count differs between runs", path)
		}
		for i := range first.Findings {
			if first.Findings[i].ID != second.Findings[i].ID ||
				first.Findings[i].Subject != second.Findings[i].Subject {
				t.Fatalf("%s: finding %d differs between runs", path, i)
			}
		}
	}
}

func TestEveryFixtureEmitsOnlyCataloguedFindings(t *testing.T) {
	for _, path := range fixturePaths(t) {
		res, _ := analyseFixture(loadFixture(t, path))
		for _, f := range res.Findings {
			m, ok := finding.Lookup(f.ID)
			if !ok {
				t.Errorf("%s: uncatalogued finding %s", path, f.ID)
				continue
			}
			if f.Severity != m.Severity || f.Control != m.Control {
				t.Errorf("%s: finding %s drifted from the catalogue", path, f.ID)
			}
		}
	}
}

func TestFixtureCorpusCoversAWideRangeOfPostures(t *testing.T) {
	best, worst := -1, 101
	grades := map[string]bool{}

	for _, path := range fixturePaths(t) {
		_, sc := analyseFixture(loadFixture(t, path))
		grades[sc.Grade] = true
		if sc.Score > best {
			best = sc.Score
		}
		if sc.Score < worst {
			worst = sc.Score
		}
	}
	if best < 85 {
		t.Errorf("the best fixture scores %d; the corpus should include a site that gets it right", best)
	}
	if worst > 60 {
		t.Errorf("the worst fixture scores %d; the corpus should include a site that gets it wrong", worst)
	}
	if len(grades) < 4 {
		t.Errorf("the corpus produces only %d distinct grades: %v", len(grades), grades)
	}
}

func TestSkippedGroupsAreExplainedRatherThanScored(t *testing.T) {
	obs := loadFixture(t, filepath.Join(fixtureDir, "github.com.json"))

	obs.TLS = nil
	obs.Skip(probe.GroupTLS)
	res, sc := analyseFixture(obs)

	for _, f := range res.Findings {
		if strings.HasPrefix(f.ID, "tls.") {
			t.Errorf("no TLS finding should survive a skipped TLS probe: %s", f.ID)
		}
	}
	if len(res.Notes) == 0 {
		t.Error("the report should say why the TLS controls are absent")
	}
	for _, c := range sc.Controls {
		if strings.HasPrefix(c.ID, "tls.") && c.Applicable {
			t.Errorf("control %s should not be scored", c.ID)
		}
	}
}

func TestFailedHTTPSRequestIsExplained(t *testing.T) {
	obs := &probe.Observation{
		SchemaVersion: probe.ObservationSchemaVersion,
		Host:          "a.test",
		HTTPS:         &probe.HTTPResponse{Error: "dial tcp: connection refused"},
	}
	res := analyze.Run(obs, time.Now())
	if len(res.Findings) != 0 {
		t.Errorf("nothing can be concluded from a failed request: %v", res.Findings)
	}
	if len(res.Notes) == 0 || !strings.Contains(res.Notes[0], "connection refused") {
		t.Errorf("notes = %v", res.Notes)
	}
}
