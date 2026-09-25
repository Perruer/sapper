package ingest

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/Perruer/sapper/pkg/graph"
	"github.com/protobom/protobom/pkg/reader"
	"github.com/protobom/protobom/pkg/sbom"
)

type edgeDirection int

const (
	notADependency edgeDirection = iota
	fromDependsOnTo
	toDependsOnFrom
)

// dependencyDirection says what an SBOM edge means for the dependency graph. protobom keeps the
// orientation of SPDX's "X_OF" relationships: in "A runtimeDependency B" A is the dependency of B.
// Treating every edge as "From depends on To" turns those into dependencies pointing the wrong way,
// which creates cycles and makes every package a dependent of every other one. Relationships that
// are not dependencies (describes, generates, documentation, tools and so on) are left out.
func dependencyDirection(t sbom.Edge_Type) edgeDirection {
	switch t {
	case sbom.Edge_contains, sbom.Edge_dependsOn, sbom.Edge_prerequisite, sbom.Edge_staticLink, sbom.Edge_dynamicLink:
		return fromDependsOnTo
	case sbom.Edge_contained_by, sbom.Edge_dependencyOf, sbom.Edge_prerequisiteFor,
		sbom.Edge_buildDependency, sbom.Edge_devDependency, sbom.Edge_runtimeDependency, sbom.Edge_testDependency,
		sbom.Edge_optionalDependency, sbom.Edge_optionalComponent, sbom.Edge_providedDependency:
		return toDependsOnFrom
	default:
		return notADependency
	}
}

func SBOM(storage graph.Storage, data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("data is empty")
	}
	// Create a new protobom reader
	r := reader.New()

	// Parse the SBOM file
	document, err := r.ParseStream(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to parse SBOM file: %w", err)
	}

	// Get the node list from the document
	nodeList := document.GetNodeList()
	if nodeList == nil {
		return nil
	}

	// Process each node in the SBOM

	nameToId := map[string]uint32{}

	for _, node := range nodeList.GetNodes() {
		purl := string(node.Purl())
		if purl == "" {
			purl = fmt.Sprintf("pkg:%s@%s", node.GetName(), node.GetVersion())
		}

		graphNode, err := graph.AddNode(storage, "library", node, purl)
		if err != nil {
			if errors.Is(err, graph.ErrNodeAlreadyExists) {
				// log.Printf("Skipping node %s: %s\n", node.GetName(), err)
			} else {
				return fmt.Errorf("failed to add node: %w", err)
			}
		}

		nameToId[node.Id] = graphNode.ID
	}

	for _, edge := range nodeList.Edges {
		direction := dependencyDirection(edge.Type)
		if direction == notADependency {
			continue
		}
		fromID, ok := nameToId[edge.From]
		if !ok {
			continue // an edge to an element that is not a node, such as the document itself
		}

		for _, to := range edge.To {
			toID, ok := nameToId[to]
			if !ok || fromID == toID {
				continue
			}
			dependentID, dependencyID := fromID, toID
			if direction == toDependsOnFrom {
				dependentID, dependencyID = toID, fromID
			}
			// Load the nodes for each edge: SetDependency saves them, and a node can take part in several edges.
			dependent, err := storage.GetNode(dependentID)
			if err != nil {
				return fmt.Errorf("failed to get node %d: %w", dependentID, err)
			}
			dependency, err := storage.GetNode(dependencyID)
			if err != nil {
				return fmt.Errorf("failed to get node %d: %w", dependencyID, err)
			}
			if err := dependent.SetDependency(storage, dependency); err != nil {
				return fmt.Errorf("failed to add edge %s -> %s: %w", edge.From, to, err)
			}
		}
	}

	return nil
}
