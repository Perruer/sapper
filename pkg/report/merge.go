package report

import (
	"sort"
	"strings"
)

// mergeAliases joins findings that describe the same vulnerability: OSV databases publish the same
// issue under several IDs (for example GHSA-... and GO-... records that both alias one CVE), and
// each becomes its own node in the graph.
func mergeAliases(findings []Finding) []Finding {
	parent := make([]int, len(findings))
	for i := range parent {
		parent[i] = i
	}
	var find func(int) int
	find = func(i int) int {
		if parent[i] != i {
			parent[i] = find(parent[i])
		}
		return parent[i]
	}
	owner := map[string]int{}
	for i, f := range findings {
		for _, name := range namesOf(f) {
			if j, ok := owner[name]; ok {
				parent[find(i)] = find(j)
			} else {
				owner[name] = i
			}
		}
	}

	groups := map[int][]Finding{}
	var order []int
	for i, f := range findings {
		root := find(i)
		if _, ok := groups[root]; !ok {
			order = append(order, root)
		}
		groups[root] = append(groups[root], f)
	}
	merged := make([]Finding, 0, len(order))
	for _, root := range order {
		merged = append(merged, mergeGroup(groups[root]))
	}
	return merged
}

func namesOf(f Finding) []string {
	names := []string{strings.ToUpper(f.ID)}
	for _, a := range f.Aliases {
		names = append(names, strings.ToUpper(a))
	}
	return names
}

func mergeGroup(group []Finding) Finding {
	if len(group) == 1 {
		return group[0]
	}
	// Name the finding after an advisory ID rather than a CVE, GHSA first as it carries a severity.
	sort.SliceStable(group, func(i, j int) bool { return idRank(group[i].ID) < idRank(group[j].ID) })
	out := group[0]
	names := map[string]bool{strings.ToUpper(out.ID): true}
	aliases := []string{}
	packages := map[string]bool{}
	products := map[string]Product{}
	suppressed := map[string]Product{}
	for _, f := range group {
		for _, n := range namesOf(f) {
			if !names[n] {
				names[n] = true
				aliases = append(aliases, n)
			}
		}
		if out.Summary == "" {
			out.Summary = f.Summary
		}
		if severityRank(f.Severity) > severityRank(out.Severity) {
			out.Severity = f.Severity
		}
		if out.KEV == nil {
			out.KEV = f.KEV
		}
		if f.EPSS != nil && (out.EPSS == nil || f.EPSS.EPSS > out.EPSS.EPSS) {
			out.EPSS = f.EPSS
		}
		for _, p := range f.Packages {
			packages[p] = true
		}
		for _, p := range f.Products {
			if _, ok := products[p.Name]; !ok {
				products[p.Name] = p
			}
		}
		for _, p := range f.Suppressed {
			if _, ok := suppressed[p.Name]; !ok {
				suppressed[p.Name] = p
			}
		}
	}
	sort.Strings(aliases)
	out.Aliases = aliases
	out.Packages = sortedKeys(packages)
	out.Products = sortedProducts(products)
	// A product suppressed by one record's VEX statement is suppressed for the whole vulnerability
	for name := range suppressed {
		delete(products, name)
	}
	out.Products = sortedProducts(products)
	out.Suppressed = nil
	if len(suppressed) > 0 {
		out.Suppressed = sortedProducts(suppressed)
	}
	return out
}

func idRank(id string) int {
	switch {
	case strings.HasPrefix(id, "GHSA-"):
		return 0
	case strings.HasPrefix(id, "CVE-"):
		return 2
	default:
		return 1
	}
}

// severityRank orders severity labels; a CVSS vector counts as known but unranked.
func severityRank(s string) int {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MODERATE", "MEDIUM":
		return 3
	case "LOW":
		return 2
	case "":
		return 0
	default:
		return 1
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedProducts(m map[string]Product) []Product {
	out := make([]Product, 0, len(m))
	for _, p := range m {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
