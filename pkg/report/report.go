// Package report answers "which of our products does this vulnerability reach, and which should we
// fix first": it walks the graph from each vulnerability up to the products (nodes nothing depends on,
// usually the root component of an SBOM), attaches KEV and EPSS data, and applies VEX statements.
package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/Perruer/sapper/pkg/graph"
	"github.com/Perruer/sapper/pkg/tools"
	"github.com/Perruer/sapper/pkg/tools/ingest"
)

// Product is a product that a vulnerability reaches, with one dependency path to it.
type Product struct {
	Name string `json:"name"`
	// Path runs from the product to the vulnerable package, both included.
	Path []string             `json:"path"`
	VEX  *ingest.VEXStatement `json:"vex,omitempty"`
}

// Finding is one vulnerability with everything needed to decide what to do about it.
type Finding struct {
	ID       string            `json:"id"`
	Aliases  []string          `json:"aliases,omitempty"`
	Summary  string            `json:"summary,omitempty"`
	Severity string            `json:"severity,omitempty"`
	KEV      *ingest.KEVEntry  `json:"kev,omitempty"`
	EPSS     *ingest.EPSSScore `json:"epss,omitempty"`
	Packages []string          `json:"packages"`
	Products []Product         `json:"products"`
	// Suppressed lists the products that a VEX statement marks not_affected or fixed.
	Suppressed []Product `json:"suppressed,omitempty"`
}

// Options narrow the report.
type Options struct {
	// Vulnerability limits the report to one vulnerability, by OSV ID or alias (for example a CVE).
	Vulnerability string
	// KEVOnly keeps only vulnerabilities in the CISA KEV catalog.
	KEVOnly bool
	// MinEPSS keeps only vulnerabilities whose EPSS score is at least this value.
	MinEPSS float64
}

// Build computes the findings, most urgent first: vulnerabilities known to be exploited (KEV), then
// by EPSS score, then by the number of products they reach.
func Build(storage graph.Storage, opts Options) ([]Finding, error) {
	keys, err := storage.GetAllKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to get all keys: %w", err)
	}
	nodes, err := storage.GetNodes(keys)
	if err != nil {
		return nil, fmt.Errorf("failed to get nodes: %w", err)
	}

	want := strings.ToUpper(strings.TrimSpace(opts.Vulnerability))
	findings := []Finding{}
	for _, node := range nodes {
		if node == nil || node.Type != tools.VulnerabilityType {
			continue
		}
		names := ingest.VulnerabilityNames(node)
		if want != "" && !contains(names, want) {
			continue
		}
		finding, err := buildFinding(storage, nodes, node, names)
		if err != nil {
			return nil, err
		}
		if opts.KEVOnly && finding.KEV == nil {
			continue
		}
		if opts.MinEPSS > 0 && (finding.EPSS == nil || finding.EPSS.EPSS < opts.MinEPSS) {
			continue
		}
		findings = append(findings, finding)
	}

	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if (a.KEV != nil) != (b.KEV != nil) {
			return a.KEV != nil
		}
		if ea, eb := epssOf(a), epssOf(b); ea != eb {
			return ea > eb
		}
		if len(a.Products) != len(b.Products) {
			return len(a.Products) > len(b.Products)
		}
		return a.ID < b.ID
	})
	return findings, nil
}

func buildFinding(storage graph.Storage, nodes map[uint32]*graph.Node, vulnNode *graph.Node, names []string) (Finding, error) {
	finding := Finding{ID: vulnNode.Name, Packages: []string{}, Products: []Product{}}
	if vuln, err := ingest.DecodeVulnerability(vulnNode.Metadata); err == nil {
		finding.Aliases = vuln.Aliases
		finding.Summary = vuln.Summary
		finding.Severity = severityOf(vuln)
	}

	for _, name := range names {
		if !strings.HasPrefix(name, "CVE-") {
			continue
		}
		if finding.KEV == nil {
			if data, err := storage.GetCustomData(ingest.KEVTag, name); err == nil && data["entry"] != nil {
				entry := &ingest.KEVEntry{}
				if json.Unmarshal(data["entry"], entry) == nil {
					finding.KEV = entry
				}
			}
		}
		if data, err := storage.GetCustomData(ingest.EPSSTag, name); err == nil && data["score"] != nil {
			score := &ingest.EPSSScore{}
			if json.Unmarshal(data["score"], score) == nil && (finding.EPSS == nil || score.EPSS > finding.EPSS.EPSS) {
				finding.EPSS = score
			}
		}
	}

	// VEX statements for this vulnerability, by product ID (usually a purl)
	vex := map[string]*ingest.VEXStatement{}
	for _, name := range names {
		data, err := storage.GetCustomData(ingest.VEXTag, name)
		if err != nil {
			continue
		}
		for product, raw := range data {
			st := &ingest.VEXStatement{}
			if json.Unmarshal(raw, st) == nil {
				vex[product] = st
			}
		}
	}

	// Walk up from the vulnerability. next[x] is the node one step closer to the vulnerability,
	// so following it from a product gives a shortest dependency path.
	next := map[uint32]uint32{}
	visited := map[uint32]bool{vulnNode.ID: true}
	queue := []uint32{vulnNode.ID}
	var products []uint32
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		node := nodes[current]
		if node == nil {
			continue
		}
		if current != vulnNode.ID && (node.Parents == nil || node.Parents.IsEmpty()) {
			products = append(products, current)
		}
		if node.Parents == nil {
			continue
		}
		for _, parent := range node.Parents.ToArray() {
			if visited[parent] {
				continue
			}
			visited[parent] = true
			next[parent] = current
			queue = append(queue, parent)
			if current == vulnNode.ID {
				if p := nodes[parent]; p != nil {
					finding.Packages = append(finding.Packages, p.Name)
				}
			}
		}
	}
	sort.Strings(finding.Packages)

	for _, id := range products {
		product := Product{Name: nodes[id].Name}
		for step := id; step != vulnNode.ID; step = next[step] {
			product.Path = append(product.Path, nodes[step].Name)
		}
		// A statement about the product, or about the vulnerable package inside it
		product.VEX = vex[product.Name]
		if product.VEX == nil && len(product.Path) > 0 {
			product.VEX = vex[product.Path[len(product.Path)-1]]
		}
		if product.VEX != nil && (product.VEX.Status == "not_affected" || product.VEX.Status == "fixed") {
			finding.Suppressed = append(finding.Suppressed, product)
		} else {
			finding.Products = append(finding.Products, product)
		}
	}
	sort.Slice(finding.Products, func(i, j int) bool { return finding.Products[i].Name < finding.Products[j].Name })
	sort.Slice(finding.Suppressed, func(i, j int) bool { return finding.Suppressed[i].Name < finding.Suppressed[j].Name })
	return finding, nil
}

// severityOf returns the severity label that OSV databases put in database_specific (GitHub:
// LOW/MODERATE/HIGH/CRITICAL), or else the first CVSS vector.
func severityOf(vuln *ingest.Vulnerability) string {
	if s, ok := vuln.DatabaseSpecific["severity"].(string); ok && s != "" {
		return strings.ToUpper(s)
	}
	for _, s := range vuln.Severity {
		if s.Score != "" {
			return s.Score
		}
	}
	return ""
}

func epssOf(f Finding) float64 {
	if f.EPSS == nil {
		return -1
	}
	return f.EPSS.EPSS
}

func contains(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}
