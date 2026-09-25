package ingest

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/Masterminds/semver"
	"github.com/Perruer/sapper/pkg/graph"
	"github.com/Perruer/sapper/pkg/tools"
)

type Vulnerability struct {
	SchemaVersion    string                 `json:"schema_version"`
	ID               string                 `json:"id"`
	Modified         string                 `json:"modified"`
	Published        string                 `json:"published"`
	Withdrawn        string                 `json:"withdrawn"`
	Aliases          []string               `json:"aliases"`
	Related          []string               `json:"related"`
	Summary          string                 `json:"summary"`
	Details          string                 `json:"details"`
	Severity         []Severity             `json:"severity"`
	Affected         []Affected             `json:"affected"`
	References       []Reference            `json:"references"`
	Credits          []Credit               `json:"credits"`
	DatabaseSpecific map[string]interface{} `json:"database_specific"`
}

type Severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type Affected struct {
	Package           Package                `json:"package"`
	Severity          []Severity             `json:"severity"`
	Ranges            []Range                `json:"ranges"`
	Versions          []string               `json:"versions"`
	EcosystemSpecific map[string]interface{} `json:"ecosystem_specific"`
	DatabaseSpecific  map[string]interface{} `json:"database_specific"`
}

type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Purl      string `json:"purl"`
}

type Range struct {
	Type             string                 `json:"type"`
	Repo             string                 `json:"repo"`
	Events           []Event                `json:"events"`
	DatabaseSpecific map[string]interface{} `json:"database_specific"`
}

type Event struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
	Limit        string `json:"limit"`
}

type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type Credit struct {
	Name    string   `json:"name"`
	Contact []string `json:"contact"`
	Type    string   `json:"type"`
}

type PairedVuln struct {
	ID   string
	Vuln Vulnerability
}

// LibraryIndex finds library nodes by package name. It keeps node IDs only: nodes are read fresh
// before they change, because a stale copy would overwrite edges added since the index was built.
type LibraryIndex struct {
	byName map[string][]indexedPackage
}

type indexedPackage struct {
	id   uint32
	info PackageInfo
}

// BuildLibraryIndex reads the graph once and indexes its library nodes.
func BuildLibraryIndex(storage graph.Storage) (*LibraryIndex, error) {
	keys, err := storage.GetAllKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to get all keys: %w", err)
	}
	nodes, err := storage.GetNodes(keys)
	if err != nil {
		return nil, fmt.Errorf("failed to get nodes from storage: %w", err)
	}
	idx := &LibraryIndex{byName: map[string][]indexedPackage{}}
	for _, node := range nodes {
		if node == nil || node.Type != tools.LibraryType || !strings.HasPrefix(node.Name, pkg) {
			continue
		}
		info, err := PURLToPackage(node.Name)
		if err != nil {
			continue
		}
		idx.byName[info.Name] = append(idx.byName[info.Name], indexedPackage{id: node.ID, info: info})
	}
	return idx, nil
}

// Vulnerabilities adds an OSV record to the graph and links it to the library nodes it affects.
func Vulnerabilities(storage graph.Storage, data []byte) error {
	idx, err := BuildLibraryIndex(storage)
	if err != nil {
		return err
	}
	return VulnerabilitiesWithIndex(storage, data, idx)
}

// VulnerabilitiesWithIndex is Vulnerabilities with a prebuilt index, for loading many OSV records.
// The index must be rebuilt after library nodes are added.
func VulnerabilitiesWithIndex(storage graph.Storage, data []byte, idx *LibraryIndex) error {
	if len(data) == 0 {
		return fmt.Errorf("data is empty")
	}

	vuln := Vulnerability{}
	if err := json.Unmarshal(data, &vuln); err != nil {
		return fmt.Errorf("failed to unmarshal vulnerabilityType data: %w", err)
	}
	vulnData, err := json.Marshal(vuln)
	if err != nil {
		return fmt.Errorf("failed to marshal vulnerability: %w", err)
	}

	seen := map[uint32]bool{}
	for _, affected := range vuln.Affected {
		for _, candidate := range idx.byName[affected.Package.Name] {
			if seen[candidate.id] || !isPackageAffected(vuln, candidate.info) {
				continue
			}
			seen[candidate.id] = true

			vulnNode, err := graph.AddNode(storage, tools.VulnerabilityType, vulnData, vuln.ID)
			if err != nil {
				return fmt.Errorf("failed to add vulnerabilityType node to storage: %w", err)
			}
			node, err := storage.GetNode(candidate.id)
			if err != nil {
				return fmt.Errorf("failed to get node %d: %w", candidate.id, err)
			}
			if err := node.SetDependency(storage, vulnNode); err != nil {
				return fmt.Errorf("failed to add dependency edge to vulnerabilityType node: %w", err)
			}
		}
	}
	return nil
}

func isPackageAffected(vuln Vulnerability, pkgInfo PackageInfo) bool {
	for _, affected := range vuln.Affected {
		if affected.Package.Name != pkgInfo.Name || affected.Package.Ecosystem != pkgInfo.Ecosystem {
			continue
		}

		if isVersionIncluded(pkgInfo.Version, affected.Versions) {
			return true
		}

		if isVersionInRanges(pkgInfo.Version, affected.Ranges, affected.Package.Ecosystem) {
			return true
		}
	}
	return false
}

func isVersionIncluded(version string, versions []string) bool {
	for _, v := range versions {
		if v == version {
			return true
		}
	}
	return false
}

func isVersionInRanges(version string, ranges []Range, ecosystem string) bool {
	for _, r := range ranges {
		vulnerable := false
		sortedEvents := sortRangeEvents(r.Events, r.Type, ecosystem)
		for _, evt := range sortedEvents {
			switch {
			case evt.Introduced == "0" || (evt.Introduced != "" && compareVersions(version, evt.Introduced, r.Type, ecosystem) >= 0):
				vulnerable = true
			case evt.Fixed != "" && compareVersions(version, evt.Fixed, r.Type, ecosystem) >= 0:
				vulnerable = false
			case evt.LastAffected != "" && compareVersions(version, evt.LastAffected, r.Type, ecosystem) > 0:
				vulnerable = false
			}
		}

		if vulnerable {
			return true
		}
	}
	return false
}

func sortRangeEvents(events []Event, eventType string, ecosystem string) []Event {
	sortedEvents := make([]Event, len(events))
	copy(sortedEvents, events)

	// Compare the elements of the slice being sorted: sort.Slice swaps sortedEvents, so indexing
	// the original events here would compare the wrong pairs.
	// "introduced": "0" means "from the very first version" and comes before everything, including
	// pre-releases such as Go pseudo-versions (0.0.0-2019...), which semver orders below 0.0.0.
	sort.SliceStable(sortedEvents, func(i, j int) bool {
		zi, zj := sortedEvents[i].Introduced == "0", sortedEvents[j].Introduced == "0"
		if zi || zj {
			return zi && !zj
		}
		vi := getVersionFromEvent(sortedEvents[i])
		vj := getVersionFromEvent(sortedEvents[j])
		return compareVersions(vi, vj, eventType, ecosystem) < 0
	})
	return sortedEvents
}

func getVersionFromEvent(evt Event) string {
	if evt.Introduced != "" {
		return evt.Introduced
	}
	if evt.Fixed != "" {
		return evt.Fixed
	}
	if evt.LastAffected != "" {
		return evt.LastAffected
	}
	return ""
}

func compareVersions(v1, v2, eventType, ecosystem string) int {
	const (
		EventTypeSEMVER    = "SEMVER"
		EventTypeECOSYSTEM = "ECOSYSTEM"
		EventTypeGIT       = "GIT"
	)
	switch eventType {
	case EventTypeSEMVER:
		ver1, err1 := semver.NewVersion(v1)
		ver2, err2 := semver.NewVersion(v2)
		if err1 != nil || err2 != nil {
			return strings.Compare(v1, v2)
		}
		return ver1.Compare(ver2)
	case EventTypeECOSYSTEM:
		return compareEcosystemVersions(v1, v2, ecosystem)
	case EventTypeGIT:
		return strings.Compare(v1, v2)
	default:
		return strings.Compare(v1, v2)
	}
}

// compareEcosystemVersions compares versions of ECOSYSTEM ranges (PyPI, Maven, RubyGems and others).
// Versions that parse as semver are compared as semver; the rest segment by segment, numbers as
// numbers, so 10.0 comes after 9.1, and 1.0rc1 before 1.0.
func compareEcosystemVersions(v1, v2, _ string) int {
	if a, err := semver.NewVersion(v1); err == nil {
		if b, err := semver.NewVersion(v2); err == nil {
			return a.Compare(b)
		}
	}
	return naturalCompare(v1, v2)
}

// versionSegments splits "1.10.0rc2" into [1 10 0 rc 2]: runs of digits and runs of letters.
func versionSegments(v string) []string {
	var parts []string
	current := ""
	digit := false
	for _, r := range strings.ToLower(strings.TrimPrefix(v, "v")) {
		isDigit := r >= '0' && r <= '9'
		isLetter := r >= 'a' && r <= 'z'
		if !isDigit && !isLetter {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
			continue
		}
		if current != "" && isDigit != digit {
			parts = append(parts, current)
			current = ""
		}
		current += string(r)
		digit = isDigit
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

func naturalCompare(v1, v2 string) int {
	a, b := versionSegments(v1), versionSegments(v2)
	for i := 0; i < len(a) || i < len(b); i++ {
		switch {
		case i >= len(a):
			// 1.0 vs 1.0.1: longer wins, but 1.0 vs 1.0rc1: a trailing word marks a pre-release
			if isWord(b[i]) && !isPostRelease(b[i]) {
				return 1
			}
			return -1
		case i >= len(b):
			if isWord(a[i]) && !isPostRelease(a[i]) {
				return -1
			}
			return 1
		}
		x, y := a[i], b[i]
		if !isWord(x) && !isWord(y) {
			nx, ny := strings.TrimLeft(x, "0"), strings.TrimLeft(y, "0")
			if len(nx) != len(ny) {
				if len(nx) < len(ny) {
					return -1
				}
				return 1
			}
			if c := strings.Compare(nx, ny); c != 0 {
				return c
			}
			continue
		}
		if isWord(x) != isWord(y) {
			// 1.0.1 vs 1.0rc1: a number is a later release than a pre-release word
			if isWord(x) {
				if isPostRelease(x) {
					return 1
				}
				return -1
			}
			if isPostRelease(y) {
				return -1
			}
			return 1
		}
		if c := strings.Compare(x, y); c != 0 {
			return c
		}
	}
	return 0
}

func isWord(s string) bool { return s != "" && (s[0] < '0' || s[0] > '9') }

func isPostRelease(s string) bool { return s == "post" || s == "p" || s == "pl" || s == "patch" }
