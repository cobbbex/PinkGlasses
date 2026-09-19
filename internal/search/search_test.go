package search

import "testing"

// A quoted value may follow a field name. The Search page narrows a query by
// a facet value exactly this way — title:"403 Forbidden" — and the lexer
// split it at the space, so the facet that promised two services found none.
func TestQuotedFieldValue(t *testing.T) {
	cases := []struct {
		q       string
		wantArg string
	}{
		{`title:"403 Forbidden"`, "%403 Forbidden%"},
		{`product:"Apache httpd"`, "Apache httpd"},
		{`title:"One moment, please..."`, "%One moment, please...%"},
		{`tech:"WordPress"`, "%WordPress%"},
		{`title:"(untitled)"`, "%(untitled)%"},
	}
	for _, c := range cases {
		got, err := Compile(c.q)
		if err != nil {
			t.Fatalf("%s: %v", c.q, err)
		}
		found := false
		for _, a := range got.Args {
			if s, ok := a.(string); ok && s == c.wantArg {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: bound args %v, want one equal to %q", c.q, got.Args, c.wantArg)
		}
		// One term binds one value; a split would have bound two.
		if len(got.Args) != 1 {
			t.Errorf("%s: compiled to %d bound values, want 1: %s", c.q, len(got.Args), got.Where)
		}
	}
}

func TestUnterminatedQuoteInFieldValue(t *testing.T) {
	if _, err := Compile(`title:"403 Forbidden`); err == nil {
		t.Error("an unterminated quote must be an error, not a term with a quote in it")
	}
}

// Free text still splits on spaces, and quoting still joins it.
func TestFreeTextTerms(t *testing.T) {
	two, err := Compile(`403 Forbidden`)
	if err != nil {
		t.Fatal(err)
	}
	if len(two.Args) != 2 {
		t.Errorf("two bare words should be two terms: %s", two.Where)
	}
	one, err := Compile(`"403 Forbidden"`)
	if err != nil {
		t.Fatal(err)
	}
	if len(one.Args) != 1 {
		t.Errorf("a quoted phrase should be one term: %s", one.Where)
	}
}
