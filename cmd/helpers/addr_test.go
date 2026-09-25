package helpers

import "testing"

func TestServerURL(t *testing.T) {
	for addr, want := range map[string]string{
		"":                        "http://localhost:8089",
		"localhost:8089":          "http://localhost:8089",
		" 10.0.0.5:9000 ":         "http://10.0.0.5:9000",
		"http://localhost:8089":   "http://localhost:8089",
		"https://sapper.acme/":    "https://sapper.acme",
		"http://127.0.0.1:18089/": "http://127.0.0.1:18089",
	} {
		if got := ServerURL(addr); got != want {
			t.Errorf("ServerURL(%q) = %q, want %q", addr, got, want)
		}
	}
}
