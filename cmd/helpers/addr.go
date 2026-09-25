package helpers

import "strings"

// ServerURL turns the --addr of a client command into the URL of the Sapper
// server. The server takes host:port, so the same value is accepted here and
// gets http:// in front; addresses with a scheme are kept as they are.
func ServerURL(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "http://localhost:8089"
	}
	if strings.Contains(addr, "://") {
		return strings.TrimRight(addr, "/")
	}
	return "http://" + strings.TrimRight(addr, "/")
}
