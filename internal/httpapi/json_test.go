package httpapi

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

type finding struct {
	ID string `json:"id"`
}

// A list endpoint with nothing to report must answer [], not null. The SPA's
// types promise arrays and read .length off them, so null crashed the page —
// an empty findings list, a run whose targets are not planned yet, and a worker
// on a finished run whose stages had all completed.
func TestWriteJSONEncodesNilSlicesAsArrays(t *testing.T) {
	cases := []struct {
		name string
		body any
		want string
	}{
		{"nil typed slice", []finding(nil), `[]`},
		{"empty slice", []finding{}, `[]`},
		{"populated slice", []finding{{ID: "x"}}, `[{"id":"x"}]`},
		{"nil slice in a composite payload",
			map[string]any{"tasks": []finding(nil)}, `{"tasks":[]}`},
		{"several, one populated",
			map[string]any{"a": []string(nil), "b": []string{"s"}},
			`{"a":[],"b":["s"]}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			writeJSON(rec, 200, c.body)
			if got := trimNL(rec.Body.String()); got != c.want {
				t.Errorf("writeJSON = %s, want %s", got, c.want)
			}
		})
	}
}

// Values that are legitimately null must stay null — the normalizer only
// touches slices, not absent objects or nil pointers.
func TestWriteJSONLeavesNonSlicesAlone(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSON(rec, 200, map[string]any{"worker_name": nil, "count": 0})
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if v, ok := got["worker_name"]; !ok || v != nil {
		t.Errorf("worker_name = %v, want null", v)
	}
}

func trimNL(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
