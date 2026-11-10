package planner

import (
	"testing"

	"github.com/benlik386/pinkglasses/internal/domain"
)

// A certificate name goes under the closest domain target it lies below;
// a name belonging to someone else goes nowhere.
func TestCertificateNamesFindTheirTarget(t *testing.T) {
	targets := []domain.RunTarget{
		{Kind: "domain", Value: "example.com"},
		{Kind: "domain", Value: "shop.example.com"},
	}
	cases := map[string]string{
		"example.com":          "example.com",
		"www.example.com":      "example.com",
		"cdn.shop.example.com": "shop.example.com",
		"badexample.com":       "",
		"example.com.evil.net": "",
	}
	for name, want := range cases {
		got := ""
		if tg := targetFor(name, targets); tg != nil {
			got = tg.Value
		}
		if got != want {
			t.Errorf("%s: under %q, want %q", name, got, want)
		}
	}
	if below("a.dev.example.com", []string{"dev.example.com"}) == "" || below("devexample.com", []string{"example.com"}) != "" {
		t.Error("below matches on label boundaries only")
	}
}
