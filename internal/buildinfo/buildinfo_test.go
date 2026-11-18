package buildinfo

import "testing"

func TestNormalizeVersion(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", DefaultLocalVersion},
		{"   ", DefaultLocalVersion},
		{"dev", DefaultLocalVersion},
		{" DEV ", DefaultLocalVersion},
		{"8.0.76-nekopara.321", "8.0.76-nekopara.321"},
		{" 8.0.57-dsh-prompt-candidate ", "8.0.57-dsh-prompt-candidate"},
	}
	for _, tc := range cases {
		if got := NormalizeVersion(tc.in); got != tc.want {
			t.Fatalf("NormalizeVersion(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
