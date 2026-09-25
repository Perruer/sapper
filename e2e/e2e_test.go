package e2e

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect"
	apiv1 "github.com/Perruer/sapper/api/v1"
	service "github.com/Perruer/sapper/gen/api/v1"
	"github.com/Perruer/sapper/pkg/graph"
	"github.com/Perruer/sapper/pkg/storages"
	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/emptypb"
)

func Test_E2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the end-to-end test in -short mode")
	}
	// Redis comes from TEST_REDIS_URL, or runs in-process (miniredis) when it is not set.
	if os.Getenv("TEST_REDIS_URL") == "" {
		t.Setenv("TEST_REDIS_URL", miniredis.RunT(t).Addr())
	}

	// Setup storage backends
	storageBackends := []struct {
		name    string
		storage graph.Storage
		cleanup func()
	}{
		func() struct {
			name    string
			storage graph.Storage
			cleanup func()
		} {
			testDBPath := filepath.Join(t.TempDir(), "test_e2e.db")
			sqlite, err := storages.SetupSQLTestDB(testDBPath)
			if err != nil {
				t.Fatal(err)
			}
			return struct {
				name    string
				storage graph.Storage
				cleanup func()
			}{
				name:    "sqlite",
				storage: sqlite,
				cleanup: func() { _ = sqlite.Close() },
			}
		}(),
		func() struct {
			name    string
			storage graph.Storage
			cleanup func()
		} {
			redis, err := storages.SetupRedisTestDB(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			return struct {
				name    string
				storage graph.Storage
				cleanup func()
			}{
				name:    "redis",
				storage: redis,
				cleanup: func() {},
			}
		}(),
	}

	for _, backend := range storageBackends {
		t.Run(backend.name, func(t *testing.T) {
			defer backend.cleanup()

			s := apiv1.NewService(backend.storage, 1)

			sbomPath := filepath.Join("..", "testdata", "sboms")
			vulnsPath := filepath.Join("..", "testdata", "osv-vulns")

			// Process SBOM files
			sbomFiles, err := os.ReadDir(sbomPath)
			assert.NoError(t, err)

			for _, file := range sbomFiles {
				if !strings.HasSuffix(file.Name(), ".json") {
					continue
				}

				data, err := os.ReadFile(filepath.Join(sbomPath, file.Name()))
				assert.NoError(t, err)

				req := connect.NewRequest(&service.IngestSBOMRequest{
					Sbom: data,
				})
				_, err = s.IngestSBOM(context.Background(), req)
				assert.NoError(t, err)
			}
			// Process vulnerability files
			vulnFiles, err := os.ReadDir(vulnsPath)
			assert.NoError(t, err)

			for _, file := range vulnFiles {
				if !strings.HasSuffix(file.Name(), ".json") {
					continue
				}

				data, err := os.ReadFile(filepath.Join(vulnsPath, file.Name()))
				assert.NoError(t, err)

				req := connect.NewRequest(&service.IngestVulnerabilityRequest{
					Vulnerability: data,
				})
				_, err = s.IngestVulnerability(context.Background(), req)
				if err != nil {
					t.Fatalf("Failed to load vulnerabilities from file %s: %v", file.Name(), err)
				}
			}

			// Cache data
			req := connect.NewRequest(&emptypb.Empty{})
			_, err = s.Cache(context.Background(), req)
			assert.NoError(t, err)

			tests := []struct {
				name               string
				script             string
				defaultNodeName    string
				queryOrLeaderboard bool
				want               uint64
				wantErr            bool
			}{
				{
					name:            "Simple dependents query",
					script:          "dependents library pkg:github/actions/checkout@v3",
					want:            6,
					defaultNodeName: "",
				},
				{
					name:            "Simple dependencies query",
					script:          "dependencies library pkg:github/actions/checkout@v3",
					want:            1,
					defaultNodeName: "",
				},
				{
					name:   "Dependents query with xor",
					script: "dependents library pkg:github/actions/checkout@v3 xor dependents library pkg:golang/gopkg.in/yaml.v3@v3.0.1",
					// 14 with protobom 0.5, which dropped the dependsOn edges of CycloneDX documents;
					// counted independently from the JSON files: 5 + 10 dependents plus the two nodes themselves.
					want:            17,
					defaultNodeName: "",
				},
				{
					name:            "Dependents query with and",
					script:          "dependents library pkg:github/actions/checkout@v3 and dependents library pkg:golang/gopkg.in/yaml.v3@v3.0.1",
					want:            0,
					defaultNodeName: "",
				},
				{
					name:            "Empty script",
					script:          "",
					want:            0,
					defaultNodeName: "",
					wantErr:         true,
				},
				{
					name:            "Invalid script",
					script:          "invalid script",
					want:            0,
					defaultNodeName: "",
					wantErr:         true,
				},
				{
					name:            "Complex nested expressions",
					script:          "(dependents library pkg:github/actions/checkout@v3 and dependents library pkg:golang/gopkg.in/yaml.v3@v3.0.1) or dependents library pkg:golang/gopkg.in/yaml.v3@v3.0.1",
					want:            11, // 8 with protobom 0.5 (see above)
					defaultNodeName: "",
					wantErr:         false,
				},
				{
					name:            "Unknown query type",
					script:          "unknown library pkg:github/actions/checkout@v3",
					want:            0,
					defaultNodeName: "",
					wantErr:         true,
				},
				{
					name:            "Missing node name",
					script:          "dependents library",
					want:            0,
					defaultNodeName: "",
					wantErr:         true,
				},
				{
					name:            "Dependencies with OR operation",
					script:          "dependencies library pkg:github/actions/checkout@v3 or dependencies library pkg:golang/gopkg.in/yaml.v3@v3.0.1",
					want:            2,
					defaultNodeName: "",
				},
				{
					name:               "Query with default node name",
					script:             "dependencies library",
					want:               950,
					queryOrLeaderboard: true,
					defaultNodeName:    "pkg:github/actions/checkout@v3",
					wantErr:            false,
				},
				{
					name:            "Complex query with multiple operations",
					script:          "((dependencies library pkg:github/actions/checkout@v3 or dependents library pkg:golang/gopkg.in/yaml.v3@v3.0.1) and dependencies library pkg:golang/gopkg.in/yaml.v3@v3.0.1) xor dependents library pkg:github/actions/checkout@v3",
					want:            6,
					defaultNodeName: "",
				},
				{
					name:            "Query with vulnerability",
					script:          "dependencies vuln pkg:github.com/google/agi@",
					want:            1,
					defaultNodeName: "",
					wantErr:         false,
				},
			}

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					if tt.queryOrLeaderboard == true {
						req := connect.NewRequest(&service.CustomLeaderboardRequest{
							Script: tt.script,
						})
						resp, err := s.CustomLeaderboard(context.Background(), req)
						if (err != nil) != tt.wantErr {
							t.Errorf("CustomLeaderboard() error = %v, wantErr %v", err, tt.wantErr)
							return
						}
						if err != nil {
							return
						}
						nodes := resp.Msg.Queries
						if len(nodes) == 0 {
							t.Errorf("CustomLeaderboard() returned no queries, expected at least one")
							return
						}
						if !tt.wantErr && len(nodes[0].Output) != int(tt.want) {
							t.Errorf("CustomLeaderboard() got the first nodes output len of = %v, want output len of %v", nodes[0].Output, tt.want)
						}
					} else {
						req := connect.NewRequest(&service.QueryRequest{
							Script: tt.script,
						})
						resp, err := s.Query(context.Background(), req)
						if (err != nil) != tt.wantErr {
							t.Errorf("Query() error = %v, wantErr %v", err, tt.wantErr)
							return
						}
						if err != nil {
							return
						}
						nodes := resp.Msg.Nodes
						if !tt.wantErr && len(nodes) != int(tt.want) {
							t.Errorf("Query() got cardinality = %v, want cardinality %v", len(nodes), tt.want)
						}
					}

				})
			}

			t.Run("Report of a CVE with KEV data", func(t *testing.T) {
				resp, err := s.Report(context.Background(), connect.NewRequest(&service.ReportRequest{Vulnerability: "CVE-2024-6345"}))
				if !assert.NoError(t, err) || !assert.Len(t, resp.Msg.Findings, 1) {
					return
				}
				f := resp.Msg.Findings[0]
				assert.Equal(t, "GHSA-cx63-2mw6-8hw5", f.Id)
				if assert.NotEmpty(t, f.Products) {
					path := f.Products[0].Path
					assert.Equal(t, "pkg:github.com/google/agi@", f.Products[0].Name)
					assert.Equal(t, "pkg:pypi/setuptools@65.5.1", path[len(path)-1])
				}
				assert.Nil(t, f.Kev)

				kev := `{"vulnerabilities":[{"cveID":"CVE-2024-6345","dateAdded":"2026-01-02","dueDate":"2026-01-23"}]}`
				_, err = s.IngestKEV(context.Background(), connect.NewRequest(&service.IngestDataRequest{Data: []byte(kev)}))
				assert.NoError(t, err)
				all, err := s.Report(context.Background(), connect.NewRequest(&service.ReportRequest{}))
				if assert.NoError(t, err) && assert.NotEmpty(t, all.Msg.Findings) {
					assert.Equal(t, "GHSA-cx63-2mw6-8hw5", all.Msg.Findings[0].Id, "the KEV vulnerability comes first")
					assert.Equal(t, "2026-01-23", all.Msg.Findings[0].Kev.DueDate)
				}
			})
		})
	}
}
