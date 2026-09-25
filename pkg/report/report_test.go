package report

import (
	"encoding/json"
	"testing"

	"github.com/Perruer/sapper/pkg/graph"
	"github.com/Perruer/sapper/pkg/storages"
	"github.com/Perruer/sapper/pkg/tools"
	"github.com/Perruer/sapper/pkg/tools/ingest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// productA -> libX -> vuln; productB -> libY -> libX; productC -> libZ
func setupGraph(t *testing.T) graph.Storage {
	t.Helper()
	s, err := storages.SetupSQLTestDB("file::memory:")
	require.NoError(t, err)

	add := func(typ, name string, meta any) *graph.Node {
		n, err := graph.AddNode(s, typ, meta, name)
		require.NoError(t, err)
		return n
	}
	link := func(from, to string) {
		fromID, err := s.NameToID(from)
		require.NoError(t, err)
		toID, err := s.NameToID(to)
		require.NoError(t, err)
		f, err := s.GetNode(fromID)
		require.NoError(t, err)
		tn, err := s.GetNode(toID)
		require.NoError(t, err)
		require.NoError(t, f.SetDependency(s, tn))
	}

	for _, name := range []string{"pkg:generic/productA@1", "pkg:generic/productB@1", "pkg:generic/productC@1",
		"pkg:golang/libX@1.0.0", "pkg:golang/libY@1.0.0", "pkg:golang/libZ@1.0.0"} {
		add(tools.LibraryType, name, nil)
	}
	osv, _ := json.Marshal(ingest.Vulnerability{
		ID:               "GHSA-aaaa-bbbb-cccc",
		Aliases:          []string{"CVE-2026-0001"},
		Summary:          "Remote code execution in libX",
		DatabaseSpecific: map[string]interface{}{"severity": "critical"},
	})
	add(tools.VulnerabilityType, "GHSA-aaaa-bbbb-cccc", osv)
	quiet, _ := json.Marshal(ingest.Vulnerability{ID: "GO-2026-0002", Summary: "DoS in libZ"})
	add(tools.VulnerabilityType, "GO-2026-0002", quiet)

	link("pkg:generic/productA@1", "pkg:golang/libX@1.0.0")
	link("pkg:generic/productB@1", "pkg:golang/libY@1.0.0")
	link("pkg:golang/libY@1.0.0", "pkg:golang/libX@1.0.0")
	link("pkg:golang/libX@1.0.0", "GHSA-aaaa-bbbb-cccc")
	link("pkg:generic/productC@1", "pkg:golang/libZ@1.0.0")
	link("pkg:golang/libZ@1.0.0", "GO-2026-0002")
	return s
}

func TestBuildFindsProductsAndPaths(t *testing.T) {
	s := setupGraph(t)
	findings, err := Build(s, Options{Vulnerability: "cve-2026-0001"})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	f := findings[0]
	assert.Equal(t, "GHSA-aaaa-bbbb-cccc", f.ID)
	assert.Equal(t, "CRITICAL", f.Severity)
	assert.Equal(t, []string{"pkg:golang/libX@1.0.0"}, f.Packages, "only the packages that contain the vulnerability")
	require.Len(t, f.Products, 2)
	assert.Equal(t, "pkg:generic/productA@1", f.Products[0].Name)
	assert.Equal(t, []string{"pkg:generic/productA@1", "pkg:golang/libX@1.0.0"}, f.Products[0].Path)
	assert.Equal(t, []string{"pkg:generic/productB@1", "pkg:golang/libY@1.0.0", "pkg:golang/libX@1.0.0"}, f.Products[1].Path)
}

func TestBuildRanksWithKEVAndEPSSAndAppliesVEX(t *testing.T) {
	s := setupGraph(t)

	n, err := ingest.KEV(s, []byte(`{"vulnerabilities":[{"cveID":"CVE-2026-0001","dateAdded":"2026-09-20","dueDate":"2026-10-11","knownRansomwareCampaignUse":"Known"}]}`))
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	epss := "#model_version:v2025.03.14,score_date:2026-09-24T12:55:00+0000\ncve,epss,percentile\nCVE-2026-0001,0.91,0.99\nCVE-1999-0001,0.5,0.5\n"
	n, err = ingest.EPSS(s, []byte(epss))
	require.NoError(t, err)
	assert.Equal(t, 1, n, "only CVEs present in the graph are stored")

	vex := `{"@context":"https://openvex.dev/ns/v0.2.0","timestamp":"2026-09-25T00:00:00Z","statements":[
	  {"vulnerability":{"name":"CVE-2026-0001"},"products":[{"@id":"pkg:generic/productB@1"}],
	   "status":"not_affected","justification":"vulnerable_code_not_in_execute_path"}]}`
	n, err = ingest.VEX(s, []byte(vex))
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	findings, err := Build(s, Options{})
	require.NoError(t, err)
	require.Len(t, findings, 2)
	top := findings[0]
	assert.Equal(t, "GHSA-aaaa-bbbb-cccc", top.ID, "the KEV vulnerability comes first")
	require.NotNil(t, top.KEV)
	assert.Equal(t, "2026-10-11", top.KEV.DueDate)
	require.NotNil(t, top.EPSS)
	assert.InDelta(t, 0.91, top.EPSS.EPSS, 1e-9)
	assert.Equal(t, "2026-09-24", top.EPSS.Date)
	require.Len(t, top.Products, 1)
	assert.Equal(t, "pkg:generic/productA@1", top.Products[0].Name)
	require.Len(t, top.Suppressed, 1)
	assert.Equal(t, "not_affected", top.Suppressed[0].VEX.Status)

	kevOnly, err := Build(s, Options{KEVOnly: true})
	require.NoError(t, err)
	assert.Len(t, kevOnly, 1)
}

func TestVEXRejectsUnknownStatus(t *testing.T) {
	s := setupGraph(t)
	_, err := ingest.VEX(s, []byte(`{"statements":[{"vulnerability":{"name":"CVE-1"},"products":[{"@id":"x"}],"status":"maybe"}]}`))
	assert.Error(t, err)
}
