package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dotMuny/httpsec/internal/finding"
	"github.com/dotMuny/httpsec/internal/score"
)

func reportWith(host string, sc int, grade string, fs ...finding.Finding) *Report {
	return &Report{
		SchemaVersion: SchemaVersion,
		GeneratedAt:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Target:        Target{Host: host},
		Score:         score.Score{Score: sc, Grade: grade},
		Findings:      fs,
	}
}

func TestCompareDetectsFixedIntroducedAndChanged(t *testing.T) {
	before := reportWith("a.test", 60, "D",
		finding.New("hsts.missing", ""),
		finding.New("nosniff.missing", ""),
		finding.New("cookie.no-secure", "").WithSubject("sid"),
		finding.New("hsts.ok", ""), // passes are not diffed
	)
	after := reportWith("a.test", 75, "C+",
		finding.New("nosniff.missing", ""),
		finding.New("cookie.session-no-httponly", "").WithSubject("sid"),
		finding.New("csp.missing", ""),
	)

	d := Compare(before, after)

	if d.ScoreDelta != 15 {
		t.Errorf("score delta = %d, want 15", d.ScoreDelta)
	}
	if !d.GradeChanged {
		t.Error("the grade changed")
	}
	if !d.SameTarget {
		t.Error("the hosts match")
	}
	if len(d.Fixed) != 2 {
		t.Errorf("fixed = %v, want hsts.missing and cookie.no-secure", d.Fixed)
	}
	if len(d.Introduced) != 2 {
		t.Errorf("introduced = %v, want csp.missing and cookie.session-no-httponly", d.Introduced)
	}
	if len(d.Changed) != 0 {
		t.Errorf("changed = %v", d.Changed)
	}
}

func TestCompareDetectsASeverityChange(t *testing.T) {
	// The same finding ID and subject with a different severity is a change,
	// not a fix plus an introduction.
	before := reportWith("a.test", 70, "C", finding.New("hsts.no-subdomains", ""))
	after := reportWith("a.test", 65, "D+", finding.New("hsts.no-subdomains", ""))
	after.Findings[0].Severity = finding.SeverityHigh

	d := Compare(before, after)
	if len(d.Changed) != 1 {
		t.Fatalf("changed = %v, want one entry", d.Changed)
	}
	if d.Changed[0].Was != finding.SeverityLow || d.Changed[0].Severity != finding.SeverityHigh {
		t.Errorf("= %+v", d.Changed[0])
	}
}

func TestCompareDifferentHosts(t *testing.T) {
	d := Compare(reportWith("a.test", 80, "B"), reportWith("b.test", 80, "B"))
	if d.SameTarget {
		t.Error("different hosts should be flagged")
	}
}

func TestImprovedAndRegressed(t *testing.T) {
	improved := Compare(
		reportWith("a.test", 60, "D", finding.New("hsts.missing", "")),
		reportWith("a.test", 80, "B"),
	)
	if !improved.Improved() || improved.Regressed() {
		t.Errorf("= improved %v regressed %v", improved.Improved(), improved.Regressed())
	}

	regressed := Compare(
		reportWith("a.test", 80, "B"),
		reportWith("a.test", 60, "D", finding.New("hsts.missing", "")),
	)
	if regressed.Improved() || !regressed.Regressed() {
		t.Errorf("= improved %v regressed %v", regressed.Improved(), regressed.Regressed())
	}

	unchanged := Compare(reportWith("a.test", 80, "B"), reportWith("a.test", 80, "B"))
	if unchanged.Improved() || unchanged.Regressed() {
		t.Error("an identical pair is neither better nor worse")
	}

	// Same score, one finding gone: still an improvement.
	fixedOnly := Compare(
		reportWith("a.test", 80, "B", finding.New("coop.missing", "")),
		reportWith("a.test", 80, "B"),
	)
	if !fixedOnly.Improved() {
		t.Error("fixing something without moving the score is still an improvement")
	}
}

func TestDiffEntriesAreSortedBySeverity(t *testing.T) {
	d := Compare(
		reportWith("a.test", 90, "A"),
		reportWith("a.test", 40, "F",
			finding.New("nosniff.missing", ""),
			finding.New("tls.version.tls10", ""),
			finding.New("coop.missing", ""),
		),
	)
	if len(d.Introduced) != 3 {
		t.Fatalf("introduced = %v", d.Introduced)
	}
	if d.Introduced[0].ID != "tls.version.tls10" {
		t.Errorf("the critical finding should come first, got %s", d.Introduced[0].ID)
	}
}

func TestDiffWriteText(t *testing.T) {
	d := Compare(
		reportWith("a.test", 60, "D", finding.New("hsts.missing", "")),
		reportWith("a.test", 80, "B", finding.New("nosniff.missing", "")),
	)
	var buf bytes.Buffer
	off := false
	d.WriteText(&buf, &off)
	out := buf.String()
	for _, want := range []string{"httpsec diff", "FIXED", "INTRODUCED", "+20 points"} {
		if !strings.Contains(out, want) {
			t.Errorf("text diff should contain %q:\n%s", want, out)
		}
	}
}

func TestDiffWriteTextWithNoChanges(t *testing.T) {
	d := Compare(reportWith("a.test", 80, "B"), reportWith("a.test", 80, "B"))
	var buf bytes.Buffer
	off := false
	d.WriteText(&buf, &off)
	if !strings.Contains(buf.String(), "No change") {
		t.Errorf("= %s", buf.String())
	}
}

func TestDiffWriteTextWarnsAboutDifferentHosts(t *testing.T) {
	d := Compare(reportWith("a.test", 80, "B"), reportWith("b.test", 80, "B"))
	var buf bytes.Buffer
	off := false
	d.WriteText(&buf, &off)
	if !strings.Contains(buf.String(), "different hosts") {
		t.Error("comparing two different hosts should be called out")
	}
}

func TestDiffWriteMarkdown(t *testing.T) {
	before := reportWith("a.test", 60, "D", finding.New("hsts.no-subdomains", ""))
	after := reportWith("a.test", 55, "F", finding.New("hsts.no-subdomains", ""), finding.New("csp.missing", ""))
	after.Findings[0].Severity = finding.SeverityMedium

	var buf bytes.Buffer
	Compare(before, after).WriteMarkdown(&buf)
	out := buf.String()
	for _, want := range []string{"## httpsec diff", "Introduced", "Severity changed", "-5 points"} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown diff should contain %q:\n%s", want, out)
		}
	}
}

func TestDiffWriteMarkdownWithNoChanges(t *testing.T) {
	var buf bytes.Buffer
	Compare(reportWith("a.test", 80, "B"), reportWith("a.test", 80, "B")).WriteMarkdown(&buf)
	if !strings.Contains(buf.String(), "No change") {
		t.Errorf("= %s", buf.String())
	}
}

func TestDiffSerialisesToJSON(t *testing.T) {
	d := Compare(
		reportWith("a.test", 60, "D", finding.New("hsts.missing", "")),
		reportWith("a.test", 80, "B"),
	)
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var back Diff
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.ScoreDelta != d.ScoreDelta || len(back.Fixed) != len(d.Fixed) {
		t.Error("the diff did not survive a JSON round trip")
	}
}
