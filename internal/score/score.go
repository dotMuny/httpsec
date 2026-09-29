package score

import (
	"math"
	"sort"

	"github.com/dotMuny/httpsec/internal/finding"
)

// ControlScore is the outcome of one rubric control on one target.
type ControlScore struct {
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	Category   string   `json:"category"`
	Weight     float64  `json:"weight"`
	Applicable bool     `json:"applicable"`
	Earned     float64  `json:"earned"`
	Lost       float64  `json:"lost"`
	Findings   []string `json:"findings,omitempty"`
	Reasons    []string `json:"reasons,omitempty"`
}

// CapApplied records a finding that limited the grade.
type CapApplied struct {
	Finding  string `json:"finding"`
	Title    string `json:"title"`
	MaxGrade string `json:"max_grade"`
	Reason   string `json:"reason"`
}

// Score is the full, explainable result of applying a rubric to findings.
type Score struct {
	RubricName    string         `json:"rubric_name"`
	RubricVersion string         `json:"rubric_version"`
	Score         int            `json:"score"`
	Grade         string         `json:"grade"`
	UncappedGrade string         `json:"uncapped_grade"`
	EarnedWeight  float64        `json:"earned_weight"`
	TotalWeight   float64        `json:"total_weight"`
	Controls      []ControlScore `json:"controls"`
	Caps          []CapApplied   `json:"caps_applied,omitempty"`
	Skipped       []string       `json:"controls_not_evaluated,omitempty"`
}

// Compute applies a rubric to a set of findings.
//
// A control with no finding at all was not evaluated: it drops out of both
// the numerator and the denominator, so a partial scan is scored on what it
// actually looked at rather than being punished for what it skipped.
func Compute(r *Rubric, findings []finding.Finding) Score {
	byControl := map[string][]finding.Finding{}
	for _, f := range findings {
		byControl[f.Control] = append(byControl[f.Control], f)
	}

	s := Score{RubricName: r.Name, RubricVersion: r.Version}

	for _, c := range r.Controls {
		cs := ControlScore{ID: c.ID, Title: c.Title, Category: c.Category, Weight: c.Weight}
		fs := byControl[c.ID]
		if len(fs) == 0 {
			s.Skipped = append(s.Skipped, c.ID)
			s.Controls = append(s.Controls, cs)
			continue
		}
		cs.Applicable = true

		penalty := 0.0
		for _, f := range fs {
			cs.Findings = append(cs.Findings, f.ID)
			p := r.Penalty(f.Severity)
			if p <= 0 {
				continue
			}
			penalty += p
			cs.Reasons = append(cs.Reasons, f.Title+" ("+string(f.Severity)+")")
		}
		penalty = math.Min(penalty, 1.0)

		cs.Lost = round2(c.Weight * penalty)
		cs.Earned = round2(c.Weight - cs.Lost)
		s.Controls = append(s.Controls, cs)
		s.TotalWeight += c.Weight
		s.EarnedWeight += cs.Earned
	}

	s.TotalWeight = round2(s.TotalWeight)
	s.EarnedWeight = round2(s.EarnedWeight)
	if s.TotalWeight > 0 {
		s.Score = int(math.Round(s.EarnedWeight / s.TotalWeight * 100))
	}
	s.UncappedGrade = r.Grade(s.Score)
	s.Grade = s.UncappedGrade

	// Critical findings cap the grade rather than merely subtracting points:
	// a site that accepts TLS 1.0 should not be able to buy its way back to
	// an A with a good CSP.
	seen := map[string]bool{}
	for _, f := range findings {
		rule, ok := r.capsBy[f.ID]
		if !ok || seen[f.ID] {
			continue
		}
		seen[f.ID] = true
		s.Caps = append(s.Caps, CapApplied{
			Finding: f.ID, Title: f.Title, MaxGrade: rule.MaxGrade, Reason: rule.Reason,
		})
		if r.GradeRank(rule.MaxGrade) > r.GradeRank(s.Grade) {
			s.Grade = rule.MaxGrade
		}
	}
	sort.Slice(s.Caps, func(i, j int) bool {
		if a, b := r.GradeRank(s.Caps[i].MaxGrade), r.GradeRank(s.Caps[j].MaxGrade); a != b {
			return a > b
		}
		return s.Caps[i].Finding < s.Caps[j].Finding
	})
	return s
}

// Passes reports whether the score meets a minimum grade, for use as a CI
// gate. An unknown minimum never passes.
func (s Score) Passes(r *Rubric, minGrade string) bool {
	if !r.ValidGrade(minGrade) {
		return false
	}
	return r.GradeRank(s.Grade) <= r.GradeRank(minGrade)
}

func round2(f float64) float64 { return math.Round(f*100) / 100 }
