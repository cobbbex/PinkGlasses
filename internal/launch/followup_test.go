package launch

import (
	"net/http"
	"strings"
	"testing"

	"github.com/benlik386/pinkglasses/internal/domain"
	"github.com/benlik386/pinkglasses/internal/store"
)

func scopeT(kind, value string, mode domain.TargetMode) domain.ScopeTarget {
	return domain.ScopeTarget{Kind: kind, Value: value, Mode: mode}
}

// A follow-up offers the parent's targets and what was found below them,
// minus anything the company has excluded since.
func TestFollowUpCandidatesDropExcluded(t *testing.T) {
	scope := []domain.ScopeTarget{
		scopeT("domain", "example.com", domain.ModeActive),
		scopeT("domain", "dev.example.com", domain.ModeExclude),
		scopeT("cidr", "203.0.113.0/28", domain.ModeActive),
		scopeT("domain", "gone.org", domain.ModeExclude),
	}
	targets := []domain.RunTarget{
		{Kind: "domain", Value: "example.com"},
		{Kind: "cidr", Value: "203.0.113.0/28"},
		{Kind: "domain", Value: "gone.org"},
	}
	found := []store.RunAsset{
		{Kind: "domain", Value: "www.example.com", Under: []string{"example.com"}},
		{Kind: "domain", Value: "api.dev.example.com", Under: []string{"example.com"}},
		{Kind: "domain", Value: "mail.gone.org", Under: []string{"gone.org"}},
		{Kind: "ip", Value: "198.51.100.7", Under: []string{"example.com", "gone.org"}},
		{Kind: "domain", Value: "example.com", Under: []string{"example.com"}},
	}
	got := map[string][]string{}
	for _, c := range candidates(scope, targets, found) {
		got[c.Kind+" "+c.Value] = c.Under
	}
	for _, want := range []string{"domain example.com", "cidr 203.0.113.0/28", "domain www.example.com", "ip 198.51.100.7"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %s", want)
		}
	}
	for _, not := range []string{"domain gone.org", "domain api.dev.example.com", "domain mail.gone.org"} {
		if _, ok := got[not]; ok {
			t.Errorf("offered %s, which is excluded", not)
		}
	}
	if u := got["ip 198.51.100.7"]; len(u) != 1 || u[0] != "example.com" {
		t.Errorf("address kept under %v; only example.com is still allowed", u)
	}
	if len(got) != 4 {
		t.Errorf("%d candidates, want 4 (the target is listed once): %v", len(got), got)
	}
}

// Naming a value the parent did not find is refused by name, not dropped.
func TestSelectSeedsRefusesUnknownValues(t *testing.T) {
	cands := []store.RunAsset{
		{Kind: "domain", Value: "www.example.com", Under: []string{"example.com"}},
		{Kind: "ip", Value: "198.51.100.7", Under: []string{"example.com"}},
	}
	all, ref := selectSeeds(cands, nil)
	if ref != nil || len(all) != 2 {
		t.Fatalf("all: %v %v", all, ref)
	}
	one, ref := selectSeeds(cands, []string{" WWW.example.com. "})
	if ref != nil || len(one) != 1 || one[0].value != "www.example.com" {
		t.Fatalf("one: %v %v", one, ref)
	}
	_, ref = selectSeeds(cands, []string{"www.example.com", "evil.net"})
	if ref == nil || ref.Status != http.StatusBadRequest || !strings.Contains(ref.Msg, "evil.net") {
		t.Fatalf("unknown value: %v", ref)
	}
	if _, ref = selectSeeds(nil, nil); ref == nil {
		t.Fatal("a run with no results started a follow-up")
	}
}
