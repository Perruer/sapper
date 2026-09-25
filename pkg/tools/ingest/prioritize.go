package ingest

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/Perruer/sapper/pkg/graph"
	"github.com/Perruer/sapper/pkg/tools"
)

// Tags of the custom data that ranks and filters vulnerabilities.
const (
	KEVTag  = "kev"  // CISA Known Exploited Vulnerabilities, keyed by CVE
	EPSSTag = "epss" // Exploit Prediction Scoring System, keyed by CVE
	VEXTag  = "vex"  // VEX statements, keyed by vulnerability, one field per product
)

// KEVEntry is one entry of the CISA KEV catalog (known_exploited_vulnerabilities.json).
type KEVEntry struct {
	CVEID                      string `json:"cveID"`
	VendorProject              string `json:"vendorProject"`
	Product                    string `json:"product"`
	VulnerabilityName          string `json:"vulnerabilityName"`
	DateAdded                  string `json:"dateAdded"`
	ShortDescription           string `json:"shortDescription"`
	RequiredAction             string `json:"requiredAction"`
	DueDate                    string `json:"dueDate"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
}

// EPSSScore is the EPSS probability of exploitation in the next 30 days and its percentile.
type EPSSScore struct {
	EPSS       float64 `json:"epss"`
	Percentile float64 `json:"percentile"`
	Date       string  `json:"date,omitempty"`
}

// VEXStatement says whether a product is affected by a vulnerability (OpenVEX statuses:
// not_affected, affected, fixed, under_investigation).
type VEXStatement struct {
	Status          string `json:"status"`
	Justification   string `json:"justification,omitempty"`
	ImpactStatement string `json:"impact_statement,omitempty"`
	ActionStatement string `json:"action_statement,omitempty"`
	Timestamp       string `json:"timestamp,omitempty"`
}

// KEV stores the entries of a CISA KEV catalog. It returns the number of entries stored.
func KEV(storage graph.Storage, data []byte) (int, error) {
	var catalog struct {
		CatalogVersion  string     `json:"catalogVersion"`
		Vulnerabilities []KEVEntry `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &catalog); err != nil {
		return 0, fmt.Errorf("failed to parse the KEV catalog: %w", err)
	}
	stored := 0
	for _, entry := range catalog.Vulnerabilities {
		cve := strings.ToUpper(strings.TrimSpace(entry.CVEID))
		if cve == "" {
			continue
		}
		value, err := json.Marshal(entry)
		if err != nil {
			return stored, err
		}
		if err := storage.AddOrUpdateCustomData(KEVTag, cve, "entry", value); err != nil {
			return stored, fmt.Errorf("failed to store KEV entry %s: %w", cve, err)
		}
		stored++
	}
	return stored, nil
}

// EPSS stores the EPSS scores of the CVEs that the vulnerabilities in the graph refer to. The daily
// file (epss_scores-YYYY-MM-DD.csv, optionally gzipped) has a "#model_version:...,score_date:..." line
// and the columns cve,epss,percentile. It returns the number of scores stored.
func EPSS(storage graph.Storage, data []byte) (int, error) {
	known, err := CVEsInGraph(storage)
	if err != nil {
		return 0, err
	}
	if len(known) == 0 {
		return 0, nil
	}
	var reader io.Reader = bytes.NewReader(data)
	if len(data) > 2 && data[0] == 0x1f && data[1] == 0x8b {
		gz, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return 0, fmt.Errorf("failed to read the gzipped EPSS file: %w", err)
		}
		defer gz.Close()
		reader = gz
	}

	buffered := bufio.NewReader(reader)
	date := ""
	if first, err := buffered.Peek(1); err == nil && first[0] == '#' {
		line, _ := buffered.ReadString('\n')
		for _, part := range strings.Split(strings.TrimSpace(strings.TrimPrefix(line, "#")), ",") {
			if k, v, ok := strings.Cut(part, ":"); ok && strings.TrimSpace(k) == "score_date" {
				date = strings.TrimSpace(v)
				if len(date) >= 10 {
					date = date[:10]
				}
			}
		}
	}

	rows := csv.NewReader(buffered)
	rows.FieldsPerRecord = -1
	header, err := rows.Read()
	if err != nil {
		return 0, fmt.Errorf("failed to read the EPSS header: %w", err)
	}
	col := map[string]int{}
	for i, name := range header {
		col[strings.ToLower(strings.TrimSpace(name))] = i
	}
	cveCol, ok1 := col["cve"]
	epssCol, ok2 := col["epss"]
	pctCol, ok3 := col["percentile"]
	if !ok1 || !ok2 || !ok3 {
		return 0, fmt.Errorf("the EPSS file needs the columns cve, epss and percentile, got %v", header)
	}

	stored := 0
	for {
		record, err := rows.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return stored, fmt.Errorf("failed to read the EPSS file: %w", err)
		}
		if len(record) <= max(cveCol, epssCol, pctCol) {
			continue
		}
		cve := strings.ToUpper(strings.TrimSpace(record[cveCol]))
		if !known[cve] {
			continue
		}
		score, err1 := strconv.ParseFloat(strings.TrimSpace(record[epssCol]), 64)
		percentile, err2 := strconv.ParseFloat(strings.TrimSpace(record[pctCol]), 64)
		if err1 != nil || err2 != nil {
			continue
		}
		value, _ := json.Marshal(EPSSScore{EPSS: score, Percentile: percentile, Date: date})
		if err := storage.AddOrUpdateCustomData(EPSSTag, cve, "score", value); err != nil {
			return stored, fmt.Errorf("failed to store the EPSS score of %s: %w", cve, err)
		}
		stored++
	}
	return stored, nil
}

// VEX stores the statements of an OpenVEX document. Each statement is kept under every name of its
// vulnerability (ID and aliases) and every product, so it matches the OSV ID or the CVE. It returns
// the number of statement/product pairs stored.
func VEX(storage graph.Storage, data []byte) (int, error) {
	var doc struct {
		Timestamp  string `json:"timestamp"`
		Statements []struct {
			Vulnerability struct {
				ID      string   `json:"@id"`
				Name    string   `json:"name"`
				Aliases []string `json:"aliases"`
			} `json:"vulnerability"`
			Products []struct {
				ID            string `json:"@id"`
				Subcomponents []struct {
					ID string `json:"@id"`
				} `json:"subcomponents"`
			} `json:"products"`
			Status          string `json:"status"`
			Justification   string `json:"justification"`
			ImpactStatement string `json:"impact_statement"`
			ActionStatement string `json:"action_statement"`
			Timestamp       string `json:"timestamp"`
		} `json:"statements"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return 0, fmt.Errorf("failed to parse the OpenVEX document: %w", err)
	}
	stored := 0
	for _, st := range doc.Statements {
		switch st.Status {
		case "not_affected", "affected", "fixed", "under_investigation":
		default:
			return stored, fmt.Errorf("unknown VEX status %q", st.Status)
		}
		timestamp := st.Timestamp
		if timestamp == "" {
			timestamp = doc.Timestamp
		}
		value, _ := json.Marshal(VEXStatement{
			Status:          st.Status,
			Justification:   st.Justification,
			ImpactStatement: st.ImpactStatement,
			ActionStatement: st.ActionStatement,
			Timestamp:       timestamp,
		})
		names := append([]string{st.Vulnerability.Name}, st.Vulnerability.Aliases...)
		for _, product := range st.Products {
			if product.ID == "" {
				continue
			}
			for _, name := range names {
				name = strings.TrimSpace(name)
				if name == "" {
					continue
				}
				if err := storage.AddOrUpdateCustomData(VEXTag, strings.ToUpper(name), product.ID, value); err != nil {
					return stored, fmt.Errorf("failed to store a VEX statement: %w", err)
				}
			}
			stored++
		}
	}
	return stored, nil
}

// CVEsInGraph returns the CVE IDs of the vulnerabilities in the graph (their OSV IDs and aliases).
func CVEsInGraph(storage graph.Storage) (map[string]bool, error) {
	keys, err := storage.GetAllKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to get all keys: %w", err)
	}
	nodes, err := storage.GetNodes(keys)
	if err != nil {
		return nil, fmt.Errorf("failed to get nodes: %w", err)
	}
	cves := map[string]bool{}
	for _, node := range nodes {
		if node == nil || node.Type != tools.VulnerabilityType {
			continue
		}
		for _, name := range VulnerabilityNames(node) {
			if strings.HasPrefix(name, "CVE-") {
				cves[name] = true
			}
		}
	}
	return cves, nil
}

// VulnerabilityNames returns the ID and aliases of a vulnerability node, upper-cased.
func VulnerabilityNames(node *graph.Node) []string {
	names := []string{strings.ToUpper(node.Name)}
	vuln, err := DecodeVulnerability(node.Metadata)
	if err != nil {
		return names
	}
	for _, alias := range vuln.Aliases {
		names = append(names, strings.ToUpper(alias))
	}
	return names
}

// DecodeVulnerability reads the OSV record kept as a vulnerability node's metadata. Stored nodes
// come back with the JSON bytes as a base64 string.
func DecodeVulnerability(metadata any) (*Vulnerability, error) {
	var raw []byte
	switch m := metadata.(type) {
	case []byte:
		raw = m
	case string:
		if decoded, err := base64.StdEncoding.DecodeString(m); err == nil {
			raw = decoded
		} else {
			raw = []byte(m)
		}
	case nil:
		return nil, fmt.Errorf("no metadata")
	default:
		var err error
		if raw, err = json.Marshal(m); err != nil {
			return nil, err
		}
	}
	vuln := &Vulnerability{}
	if err := json.Unmarshal(raw, vuln); err != nil {
		return nil, fmt.Errorf("failed to decode the OSV record: %w", err)
	}
	return vuln, nil
}
