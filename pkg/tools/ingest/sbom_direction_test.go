package ingest

import (
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
)

func TestDependencyDirection(t *testing.T) {
	cases := map[sbom.Edge_Type]edgeDirection{
		sbom.Edge_dependsOn:          fromDependsOnTo,
		sbom.Edge_contains:           fromDependsOnTo,
		sbom.Edge_dependencyOf:       toDependsOnFrom,
		sbom.Edge_runtimeDependency:  toDependsOnFrom,
		sbom.Edge_devDependency:      toDependsOnFrom,
		sbom.Edge_optionalComponent:  toDependsOnFrom,
		sbom.Edge_contained_by:       toDependsOnFrom,
		sbom.Edge_describes:          notADependency,
		sbom.Edge_documentation:      notADependency,
		sbom.Edge_buildTool:          notADependency,
		sbom.Edge_generates:          notADependency,
		sbom.Edge_UNKNOWN:            notADependency,
		sbom.Edge_providedDependency: toDependsOnFrom,
	}
	for edgeType, want := range cases {
		if got := dependencyDirection(edgeType); got != want {
			t.Errorf("dependencyDirection(%s) = %d, want %d", edgeType, got, want)
		}
	}
}
