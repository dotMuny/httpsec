package score

import (
	"testing"

	"github.com/dotMuny/httpsec/internal/finding"
)

func TestEmbeddedRubricIsConsistentWithTheCatalogue(t *testing.T) {
	r := Default()

	known := map[string]bool{}
	for _, c := range r.Controls {
		if known[c.ID] {
			t.Errorf("control %s is declared twice", c.ID)
		}
		known[c.ID] = true
	}

	// Every control a finding points at must exist, or the finding would
	// silently score nothing.
	for _, id := range finding.CatalogIDs() {
		m, _ := finding.Lookup(id)
		if !known[m.Control] {
			t.Errorf("finding %s points at control %q, which is not in the rubric", id, m.Control)
		}
	}

	// Every control must be reachable from at least one finding, or its
	// weight can never be earned or lost.
	used := map[string]bool{}
	for _, id := range finding.CatalogIDs() {
		m, _ := finding.Lookup(id)
		used[m.Control] = true
	}
	for _, c := range r.Controls {
		if !used[c.ID] {
			t.Errorf("control %s has no findings, so its weight is unreachable", c.ID)
		}
	}

	// Every cap must name a real finding, and a critical or high one at that.
	for _, c := range r.Caps {
		m, ok := finding.Lookup(c.Finding)
		if !ok {
			t.Errorf("cap references unknown finding %s", c.Finding)
			continue
		}
		if !m.Severity.IsProblem() {
			t.Errorf("cap %s has severity %s; capping the grade on a non-problem makes no sense", c.Finding, m.Severity)
		}
		if !r.ValidGrade(c.MaxGrade) {
			t.Errorf("cap %s names unknown grade %s", c.Finding, c.MaxGrade)
		}
	}
}

func TestSeverityPenaltiesAreMonotonic(t *testing.T) {
	r := Default()
	order := []finding.Severity{
		finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium,
		finding.SeverityLow, finding.SeverityInfo,
	}
	for i := 1; i < len(order); i++ {
		if r.Penalty(order[i-1]) < r.Penalty(order[i]) {
			t.Errorf("%s penalty (%.2f) should not be below %s (%.2f)",
				order[i-1], r.Penalty(order[i-1]), order[i], r.Penalty(order[i]))
		}
	}
	if r.Penalty(finding.SeverityPass) != 0 {
		t.Error("a pass must never cost points")
	}
	if r.Penalty("made-up") != 0 {
		t.Error("an unknown severity should cost nothing")
	}
}

func TestPerfectScore(t *testing.T) {
	var fs []finding.Finding
	for _, c := range Default().Controls {
		fs = append(fs, passFindingFor(t, c.ID))
	}
	s := Compute(Default(), fs)
	if s.Score != 100 {
		t.Errorf("score = %d, want 100", s.Score)
	}
	if s.Grade != "A+" {
		t.Errorf("grade = %s, want A+", s.Grade)
	}
	if len(s.Skipped) != 0 {
		t.Errorf("no control should be skipped: %v", s.Skipped)
	}
}

// passFindingFor returns any pass-severity finding attached to a control.
func passFindingFor(t *testing.T, control string) finding.Finding {
	t.Helper()
	for _, id := range finding.CatalogIDs() {
		m, _ := finding.Lookup(id)
		if m.Control == control && m.Severity == finding.SeverityPass {
			return finding.New(id, "")
		}
	}
	t.Fatalf("control %s has no pass finding", control)
	return finding.Finding{}
}

func TestUnevaluatedControlsDropOutOfBothSides(t *testing.T) {
	// A headers-only scan should not be punished for the TLS controls it
	// never looked at.
	fs := []finding.Finding{finding.New("hsts.ok", "")}
	s := Compute(Default(), fs)

	if s.TotalWeight != 10 {
		t.Errorf("total weight = %.1f, want just the hsts control's 10", s.TotalWeight)
	}
	if s.Score != 100 {
		t.Errorf("score = %d, want 100", s.Score)
	}
	if len(s.Skipped) == 0 {
		t.Error("the unevaluated controls should be listed")
	}
	for _, c := range s.Controls {
		if c.ID == "tls.versions" && c.Applicable {
			t.Error("tls.versions should not be applicable")
		}
	}
}

func TestPenaltiesAccumulateButCannotExceedTheWeight(t *testing.T) {
	// Five insecure cookies cannot cost more than the cookie control is worth.
	fs := []finding.Finding{
		finding.New("cookie.no-secure", "").WithSubject("a"),
		finding.New("cookie.no-secure", "").WithSubject("b"),
		finding.New("cookie.no-secure", "").WithSubject("c"),
		finding.New("cookie.no-httponly", "").WithSubject("a"),
		finding.New("cookie.no-samesite", "").WithSubject("a"),
	}
	s := Compute(Default(), fs)
	var cookies ControlScore
	for _, c := range s.Controls {
		if c.ID == "cookies" {
			cookies = c
		}
	}
	if cookies.Earned != 0 {
		t.Errorf("earned = %.1f, want 0", cookies.Earned)
	}
	if cookies.Lost != cookies.Weight {
		t.Errorf("lost = %.1f, want the full weight %.1f", cookies.Lost, cookies.Weight)
	}
}

func TestSinglePenaltyIsProportionalToSeverity(t *testing.T) {
	cases := []struct {
		id   string
		want float64 // fraction of the weight that survives
	}{
		{"hsts.missing", 0.2},        // high  -> 0.8 lost
		{"hsts.max-age-low", 0.5},    // medium -> 0.5 lost
		{"hsts.no-subdomains", 0.75}, // low -> 0.25 lost
		{"hsts.no-preload", 1.0},     // info -> nothing lost
	}
	for _, c := range cases {
		s := Compute(Default(), []finding.Finding{finding.New(c.id, "")})
		got := s.EarnedWeight / s.TotalWeight
		if diff := got - c.want; diff > 0.001 || diff < -0.001 {
			t.Errorf("%s: kept %.3f of the weight, want %.3f", c.id, got, c.want)
		}
	}
}

func TestCapsLimitTheGradeWithoutChangingTheScore(t *testing.T) {
	// A site that is otherwise flawless but accepts TLS 1.0.
	var fs []finding.Finding
	for _, c := range Default().Controls {
		if c.ID == "tls.versions" {
			continue
		}
		fs = append(fs, passFindingFor(t, c.ID))
	}
	fs = append(fs, finding.New("tls.version.tls10", ""))

	s := Compute(Default(), fs)
	if s.UncappedGrade != "A+" && s.UncappedGrade != "A" {
		t.Errorf("uncapped grade = %s; the score should still be high", s.UncappedGrade)
	}
	if s.Grade != "C" {
		t.Errorf("grade = %s, want C (capped by tls.version.tls10)", s.Grade)
	}
	if len(s.Caps) != 1 || s.Caps[0].Finding != "tls.version.tls10" {
		t.Errorf("caps = %+v", s.Caps)
	}
}

func TestWorstCapWins(t *testing.T) {
	fs := []finding.Finding{
		finding.New("tls.version.tls11", ""), // caps at B
		finding.New("tls.cert.expired", ""),  // caps at F
		finding.New("tls.version.tls10", ""), // caps at C
	}
	s := Compute(Default(), fs)
	if s.Grade != "F" {
		t.Errorf("grade = %s, want F: the strictest cap applies", s.Grade)
	}
	if len(s.Caps) != 3 {
		t.Errorf("all three caps should be recorded, got %d", len(s.Caps))
	}
	if s.Caps[0].MaxGrade != "F" {
		t.Errorf("caps should be listed strictest first, got %s", s.Caps[0].MaxGrade)
	}
}

func TestCapsAreNotDuplicated(t *testing.T) {
	fs := []finding.Finding{
		finding.New("tls.cipher.insecure", "").WithSubject("RC4"),
		finding.New("tls.cipher.insecure", "").WithSubject("3DES"),
	}
	s := Compute(Default(), fs)
	if len(s.Caps) != 1 {
		t.Errorf("the same cap should be recorded once, got %d", len(s.Caps))
	}
}

func TestGradeBands(t *testing.T) {
	r := Default()
	cases := map[int]string{100: "A+", 95: "A+", 94: "A", 90: "A", 89: "B+", 80: "B", 70: "C", 60: "D", 59: "F", 0: "F"}
	for score, want := range cases {
		if got := r.Grade(score); got != want {
			t.Errorf("Grade(%d) = %s, want %s", score, got, want)
		}
	}
}

func TestGradeRankAndValidity(t *testing.T) {
	r := Default()
	if r.GradeRank("A+") >= r.GradeRank("F") {
		t.Error("A+ should rank better than F")
	}
	if r.GradeRank("Z") <= r.GradeRank("F") {
		t.Error("an unknown grade should rank worst, which is the safe direction for a gate")
	}
	if !r.ValidGrade("B+") || r.ValidGrade("B-") {
		t.Error("ValidGrade is wrong")
	}
	if len(r.GradeNames()) != len(r.Grades) {
		t.Error("GradeNames should list every band")
	}
}

func TestPasses(t *testing.T) {
	r := Default()
	s := Score{Grade: "B"}
	if !s.Passes(r, "B") {
		t.Error("B should pass a B threshold")
	}
	if !s.Passes(r, "C") {
		t.Error("B should pass a C threshold")
	}
	if s.Passes(r, "A") {
		t.Error("B should not pass an A threshold")
	}
	if s.Passes(r, "nonsense") {
		t.Error("an unknown threshold must never pass")
	}
}

func TestControlLookup(t *testing.T) {
	r := Default()
	if c, ok := r.Control("hsts"); !ok || c.Weight <= 0 {
		t.Errorf("hsts control = %+v %v", c, ok)
	}
	if _, ok := r.Control("nope"); ok {
		t.Error("an unknown control should not resolve")
	}
}

func TestParseRubricRejectsNonsense(t *testing.T) {
	cases := []string{
		`{"controls": [], "grades": [{"grade":"A","min_score":0}]}`,
		`{"controls": [{"id":"a","weight":1}], "grades": []}`,
		`{"controls": [{"id":"a","weight":-1}], "grades": [{"grade":"A","min_score":0}]}`,
		`not json`,
	}
	for _, c := range cases {
		if _, err := ParseRubric([]byte(c)); err == nil {
			t.Errorf("ParseRubric(%q) should have failed", c)
		}
	}
}

func TestEmptyFindingsScoresZeroWithoutDividingByZero(t *testing.T) {
	s := Compute(Default(), nil)
	if s.Score != 0 || s.TotalWeight != 0 {
		t.Errorf("= %+v", s)
	}
	if s.Grade != "F" {
		t.Errorf("grade = %s", s.Grade)
	}
}
