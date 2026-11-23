package validation

import "testing"

func TestAPIRefPicksTheBranchToCompareWith(t *testing.T) {
	onAPI := func(names ...string) func(string) bool {
		return func(branch string) bool {
			for _, n := range names {
				if n == branch {
					return true
				}
			}
			return false
		}
	}
	cases := []struct {
		name     string
		branches []string
		exists   func(string) bool
		want     string
	}{
		{"same-named PR branch", []string{"spec/x", "12/merge"}, onAPI("spec/x", "main"), "spec/x"},
		{"no same-named branch", []string{"fix/y", "13/merge"}, onAPI("main"), "develop"},
		{"push to develop", []string{"", "develop"}, onAPI("develop", "main"), "develop"},
		// The API's main is released after this service, so main compares with develop.
		{"push to main", []string{"", "main"}, onAPI("develop", "main"), "develop"},
		{"develop to main PR", []string{"develop", "14/merge"}, onAPI("develop", "main"), "develop"},
	}
	for _, c := range cases {
		if got := apiRef(c.branches, c.exists); got != c.want {
			t.Errorf("%s: apiRef(%v) = %q, want %q", c.name, c.branches, got, c.want)
		}
	}
}
