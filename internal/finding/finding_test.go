package finding

import (
	"strings"
	"testing"
)

func TestCatalogueIsWellFormed(t *testing.T) {
	cat := Catalog()
	if len(cat) < 50 {
		t.Fatalf("the catalogue has only %d entries, which cannot be right", len(cat))
	}
	validCategory := map[string]bool{}
	for _, c := range CategoryOrder {
		validCategory[c] = true
	}

	for id, m := range cat {
		if m.Title == "" {
			t.Errorf("%s has no title", id)
		}
		if m.Why == "" {
			t.Errorf("%s has no explanation of why it matters", id)
		}
		if !m.Severity.Valid() {
			t.Errorf("%s has invalid severity %q", id, m.Severity)
		}
		if !validCategory[m.Category] {
			t.Errorf("%s has unknown category %q", id, m.Category)
		}
		if m.Control == "" {
			t.Errorf("%s is not attached to a scoring control", id)
		}
		if m.Remediation == "" {
			t.Errorf("%s has no remediation key", id)
		}
		if !strings.Contains(id, ".") {
			t.Errorf("%s should be a dotted identifier", id)
		}
		if strings.ToLower(id) != id {
			t.Errorf("%s should be lowercase", id)
		}
	}
}

func TestCatalogIDsAreSorted(t *testing.T) {
	ids := CatalogIDs()
	for i := 1; i < len(ids); i++ {
		if ids[i-1] > ids[i] {
			t.Fatalf("CatalogIDs is not sorted at %d: %s > %s", i, ids[i-1], ids[i])
		}
	}
}

func TestNewCopiesCatalogueMetadata(t *testing.T) {
	f := New("hsts.missing", "detail here").WithEvidence("raw").WithSubject("Strict-Transport-Security")
	if f.ID != "hsts.missing" || f.Detail != "detail here" || f.Evidence != "raw" {
		t.Errorf("= %+v", f)
	}
	m, _ := Lookup("hsts.missing")
	if f.Title != m.Title || f.Severity != m.Severity || f.Why != m.Why || f.Control != m.Control {
		t.Error("New should copy the catalogue metadata verbatim")
	}
}

func TestNewPanicsOnUnknownID(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("New should panic on an ID that is not in the catalogue")
		}
	}()
	New("definitely.not.a.real.finding", "")
}

func TestSeverityOrdering(t *testing.T) {
	want := []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo, SeverityPass}
	for i := 1; i < len(want); i++ {
		if want[i-1].Rank() >= want[i].Rank() {
			t.Errorf("%s should rank ahead of %s", want[i-1], want[i])
		}
	}
	if Severity("nonsense").Rank() <= SeverityPass.Rank() {
		t.Error("an unknown severity should sort last")
	}
	if Severity("nonsense").Valid() {
		t.Error("an unknown severity is not valid")
	}
}

func TestIsProblem(t *testing.T) {
	for _, s := range []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow} {
		if !s.IsProblem() {
			t.Errorf("%s should be a problem", s)
		}
	}
	for _, s := range []Severity{SeverityInfo, SeverityPass} {
		if s.IsProblem() {
			t.Errorf("%s should not be a problem", s)
		}
	}
}

func TestSortIsStableAndDeterministic(t *testing.T) {
	fs := []Finding{
		New("cookie.no-secure", "").WithSubject("b"),
		New("tls.version.tls10", ""),
		New("cookie.no-secure", "").WithSubject("a"),
		New("hsts.ok", ""),
		New("nosniff.missing", ""),
	}
	Sort(fs)

	if fs[0].ID != "tls.version.tls10" {
		t.Errorf("the critical finding should come first, got %s", fs[0].ID)
	}
	if fs[len(fs)-1].ID != "hsts.ok" {
		t.Errorf("passes should come last, got %s", fs[len(fs)-1].ID)
	}
	// Equal severity and ID: sorted by subject.
	var subjects []string
	for _, f := range fs {
		if f.ID == "cookie.no-secure" {
			subjects = append(subjects, f.Subject)
		}
	}
	if len(subjects) != 2 || subjects[0] != "a" || subjects[1] != "b" {
		t.Errorf("subjects = %v, want [a b]", subjects)
	}
}

func TestProblemsAndCounts(t *testing.T) {
	fs := []Finding{
		New("tls.version.tls10", ""),
		New("hsts.missing", ""),
		New("hsts.ok", ""),
		New("coep.missing", ""),
	}
	if got, want := len(Problems(fs)), 2; got != want {
		t.Errorf("Problems = %d, want %d", got, want)
	}
	counts := CountBySeverity(fs)
	if counts[SeverityCritical] != 1 || counts[SeverityHigh] != 1 || counts[SeverityPass] != 1 || counts[SeverityInfo] != 1 {
		t.Errorf("counts = %v", counts)
	}
}

func TestEveryCategoryHasATitle(t *testing.T) {
	for _, c := range CategoryOrder {
		if CategoryTitles[c] == "" {
			t.Errorf("category %s has no title", c)
		}
	}
}
