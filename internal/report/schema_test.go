package report

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// schemaGolden records the exact shape of the JSON report. Other tools parse
// this document, so a change to it is a breaking change whether or not anyone
// noticed while making it.
const schemaGolden = "../../testdata/report-schema.txt"

// TestJSONSchemaIsStable fails when the Report structure changes without
// SchemaVersion being bumped and the golden file regenerated.
//
//	go test ./internal/report -run TestJSONSchemaIsStable -update
func TestJSONSchemaIsStable(t *testing.T) {
	got := describeType(reflect.TypeOf(Report{}), map[reflect.Type]bool{}, 0)
	got = fmt.Sprintf("schema_version %d\n%s", SchemaVersion, got)

	if os.Getenv("HTTPSEC_UPDATE_GOLDEN") != "" {
		if err := os.MkdirAll(filepath.Dir(schemaGolden), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(schemaGolden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Log("golden schema updated")
		return
	}

	want, err := os.ReadFile(schemaGolden)
	if err != nil {
		t.Fatalf("cannot read the golden schema: %v\nRegenerate it with HTTPSEC_UPDATE_GOLDEN=1 go test ./internal/report", err)
	}
	if got != string(want) {
		t.Errorf(`the JSON report structure changed.

Other tools consume this document. If the change is intentional:
  1. bump report.SchemaVersion (currently %d) and report.Load's check,
  2. regenerate the golden file:
         HTTPSEC_UPDATE_GOLDEN=1 go test ./internal/report
  3. say so in the README.

--- want ---
%s
--- got ---
%s`, SchemaVersion, want, got)
	}
}

// describeType renders a stable, readable description of a type's JSON shape.
func describeType(t reflect.Type, seen map[reflect.Type]bool, depth int) string {
	if depth > 12 {
		return "...\n"
	}
	switch t.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Array:
		return describeType(t.Elem(), seen, depth)
	case reflect.Map:
		return "map[" + t.Key().String() + "]" + strings.TrimSpace(describeType(t.Elem(), seen, depth+1)) + "\n"
	case reflect.Struct:
		if t.PkgPath() == "time" {
			return "time.Time\n"
		}
		if seen[t] {
			return "<recursive " + t.String() + ">\n"
		}
		seen[t] = true
		defer delete(seen, t)

		type field struct{ line, nested string }
		var fields []field
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.PkgPath != "" {
				continue // unexported fields are not part of the document
			}
			tag := f.Tag.Get("json")
			name, opts, _ := strings.Cut(tag, ",")
			if name == "-" {
				continue
			}
			if name == "" {
				name = f.Name
			}
			kind := jsonKind(f.Type)
			line := fmt.Sprintf("%s%s: %s", strings.Repeat("  ", depth+1), name, kind)
			if strings.Contains(opts, "omitempty") {
				line += " (omitempty)"
			}
			nested := ""
			if base := baseType(f.Type); base.Kind() == reflect.Struct || base.Kind() == reflect.Map {
				nested = describeType(base, seen, depth+1)
			}
			fields = append(fields, field{line, nested})
		}
		sort.Slice(fields, func(i, j int) bool { return fields[i].line < fields[j].line })

		var b strings.Builder
		b.WriteString(t.String() + "\n")
		for _, f := range fields {
			b.WriteString(f.line + "\n")
			if f.nested != "" && !strings.HasPrefix(f.nested, "time.Time") {
				for _, l := range strings.Split(strings.TrimRight(f.nested, "\n"), "\n") {
					b.WriteString(strings.Repeat("  ", depth+2) + l + "\n")
				}
			}
		}
		return b.String()
	default:
		return t.Kind().String() + "\n"
	}
}

func baseType(t reflect.Type) reflect.Type {
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Array {
		t = t.Elem()
	}
	return t
}

func jsonKind(t reflect.Type) string {
	switch t.Kind() {
	case reflect.Pointer:
		return jsonKind(t.Elem()) + "?"
	case reflect.Slice, reflect.Array:
		return "[]" + jsonKind(t.Elem())
	case reflect.Map:
		return "map[" + t.Key().Kind().String() + "]" + jsonKind(t.Elem())
	case reflect.Struct:
		if t.PkgPath() == "time" {
			return "time.Time"
		}
		return t.String()
	default:
		return t.Kind().String()
	}
}
