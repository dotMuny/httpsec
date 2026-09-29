// Package score turns findings into a number and a letter, and can explain
// exactly how it got there.
//
// The rubric lives in data/rubric.json rather than in this file on purpose:
// a scoring system nobody can audit is a scoring system nobody should trust.
package score

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/dotMuny/httpsec/data"
	"github.com/dotMuny/httpsec/internal/finding"
)

// Control is one weighted item of the rubric.
type Control struct {
	ID       string  `json:"id"`
	Category string  `json:"category"`
	Weight   float64 `json:"weight"`
	Title    string  `json:"title"`
}

// Cap is a finding that limits the maximum grade regardless of the score.
type Cap struct {
	Finding  string `json:"finding"`
	MaxGrade string `json:"max_grade"`
	Reason   string `json:"reason"`
}

// GradeBand maps a minimum score to a letter.
type GradeBand struct {
	Grade    string `json:"grade"`
	MinScore int    `json:"min_score"`
}

// Rubric is the full scoring configuration.
type Rubric struct {
	SchemaVersion   int                          `json:"schema_version"`
	Name            string                       `json:"name"`
	Version         string                       `json:"version"`
	Notes           string                       `json:"notes"`
	SeverityPenalty map[finding.Severity]float64 `json:"severity_penalty"`
	Controls        []Control                    `json:"controls"`
	Caps            []Cap                        `json:"caps"`
	Grades          []GradeBand                  `json:"grades"`

	byID   map[string]Control
	capsBy map[string]Cap
}

var defaultRubric *Rubric

func init() {
	r, err := ParseRubric(data.Rubric)
	if err != nil {
		panic("score: cannot parse embedded rubric.json: " + err.Error())
	}
	defaultRubric = r
}

// Default returns the embedded rubric.
func Default() *Rubric { return defaultRubric }

// ParseRubric loads a rubric from JSON and validates it.
func ParseRubric(b []byte) (*Rubric, error) {
	var r Rubric
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	if len(r.Controls) == 0 {
		return nil, fmt.Errorf("rubric has no controls")
	}
	if len(r.Grades) == 0 {
		return nil, fmt.Errorf("rubric has no grade bands")
	}
	r.byID = make(map[string]Control, len(r.Controls))
	for _, c := range r.Controls {
		if c.Weight < 0 {
			return nil, fmt.Errorf("control %s has a negative weight", c.ID)
		}
		r.byID[c.ID] = c
	}
	r.capsBy = make(map[string]Cap, len(r.Caps))
	for _, c := range r.Caps {
		r.capsBy[c.Finding] = c
	}
	sort.SliceStable(r.Grades, func(i, j int) bool { return r.Grades[i].MinScore > r.Grades[j].MinScore })
	return &r, nil
}

// Control returns a control by ID.
func (r *Rubric) Control(id string) (Control, bool) {
	c, ok := r.byID[id]
	return c, ok
}

// Penalty returns the fraction of a control's weight lost for a severity.
func (r *Rubric) Penalty(s finding.Severity) float64 {
	if p, ok := r.SeverityPenalty[s]; ok {
		return p
	}
	return 0
}

// Grade converts a score to a letter.
func (r *Rubric) Grade(score int) string {
	for _, g := range r.Grades {
		if score >= g.MinScore {
			return g.Grade
		}
	}
	return r.Grades[len(r.Grades)-1].Grade
}

// GradeRank returns the position of a grade, 0 being the best. An unknown
// grade ranks worst, which is the safe direction for a CI gate.
func (r *Rubric) GradeRank(grade string) int {
	for i, g := range r.Grades {
		if g.Grade == grade {
			return i
		}
	}
	return len(r.Grades)
}

// ValidGrade reports whether grade is one of the rubric's letters.
func (r *Rubric) ValidGrade(grade string) bool {
	for _, g := range r.Grades {
		if g.Grade == grade {
			return true
		}
	}
	return false
}

// GradeNames lists the letters from best to worst.
func (r *Rubric) GradeNames() []string {
	out := make([]string, 0, len(r.Grades))
	for _, g := range r.Grades {
		out = append(out, g.Grade)
	}
	return out
}
