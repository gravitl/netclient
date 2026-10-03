package config

import "testing"

func TestDesiredSignatureIgnoresOrdering(t *testing.T) {
	a := desiredSignature(
		map[string]*nameserver{
			"hosted.nm": {ips: []string{"127.51.8.21", "10.0.0.1"}, isSearchDomain: true},
			"corp.lan":  {ips: []string{"10.0.0.2"}},
		},
		[]string{"127.51.8.21", "10.0.0.1"},
		[]string{"hosted.nm", "corp.lan"},
	)
	b := desiredSignature(
		map[string]*nameserver{
			"corp.lan":  {ips: []string{"10.0.0.2"}},
			"hosted.nm": {ips: []string{"10.0.0.1", "127.51.8.21"}, isSearchDomain: true},
		},
		[]string{"10.0.0.1", "127.51.8.21"},
		[]string{"corp.lan", "hosted.nm"},
	)
	if a != b {
		t.Fatalf("signature changed with ordering only:\n%q\n%q", a, b)
	}
}

func TestDesiredSignatureDetectsChanges(t *testing.T) {
	base := desiredSignature(
		map[string]*nameserver{"hosted.nm": {ips: []string{"127.51.8.21"}}},
		nil,
		[]string{"hosted.nm"},
	)

	cases := map[string]string{
		"split to full DNS": desiredSignature(
			nil,
			[]string{"127.51.8.21"},
			[]string{"hosted.nm"},
		),
		"nameserver changed": desiredSignature(
			map[string]*nameserver{"hosted.nm": {ips: []string{"10.0.0.1"}}},
			nil,
			[]string{"hosted.nm"},
		),
		"search domain flag flipped": desiredSignature(
			map[string]*nameserver{"hosted.nm": {ips: []string{"127.51.8.21"}, isSearchDomain: true}},
			nil,
			[]string{"hosted.nm"},
		),
		"match domain added": desiredSignature(
			map[string]*nameserver{
				"hosted.nm": {ips: []string{"127.51.8.21"}},
				"corp.lan":  {ips: []string{"127.51.8.21"}},
			},
			nil,
			[]string{"hosted.nm"},
		),
		"everything removed": desiredSignature(nil, nil, nil),
	}

	for name, sig := range cases {
		if sig == base {
			t.Errorf("%s: signature did not change, would skip reapply", name)
		}
	}
}
