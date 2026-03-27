package graph

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/JamesOlaitan/accessgraph/internal/model"
)

// bfsItem is an element in the BFS work queue. It carries the complete path
// from the BFS origin to the current node so that each discovered attack path
// can be materialised without a separate parent-pointer reconstruction pass.
type bfsItem struct {
	// nodeID is the graph node being visited in this queue entry.
	nodeID string

	// depth is the number of edges traversed to reach nodeID from the origin.
	depth int

	// pathNodes is the ordered slice of node IDs from the origin to nodeID,
	// inclusive of both endpoints.
	pathNodes []string

	// pathEdges is the ordered slice of edge IDs corresponding to each hop in
	// pathNodes. len(pathEdges) == len(pathNodes)-1 always holds.
	pathEdges []string
}

// BFS performs a breadth-first traversal of the graph starting from
// fromPrincipalID and collects all attack paths that reach a sensitive resource
// within maxHops steps.
//
// The traversal is iterative (queue-based) to avoid stack-overflow on large graphs.
// Each node is visited at most once; a node's depth is set on first encounter and
// never overwritten (standard BFS shortest-path semantics).
//
// Parameters:
//   - ctx: context for cancellation; checked between each hop.
//   - fromPrincipalID: the node ID of the starting principal.
//   - maxHops: maximum edge depth to explore; must be >= 1.
//
// Returns:
//   - []*model.AttackPath sorted by HopCount ascending; never nil, may be empty.
//
// Errors:
//   - ErrNotFound if fromPrincipalID does not exist in the graph.
//   - ErrInvalidInput if maxHops < 1.
//   - context.Canceled / context.DeadlineExceeded if ctx is done mid-traversal.
func (e *Engine) BFS(ctx context.Context, fromPrincipalID string, maxHops int) ([]*model.AttackPath, error) {
	if maxHops < 1 {
		return nil, fmt.Errorf("BFS: maxHops must be >= 1: %w", ErrInvalidInput)
	}
	if _, exists := e.nodes[fromPrincipalID]; !exists {
		return nil, fmt.Errorf("BFS: node %q: %w", fromPrincipalID, ErrNotFound)
	}

	var paths []*model.AttackPath

	// visited records every node ID that has been dequeued. On first encounter
	// the node is added; subsequent encounters are skipped to prevent cycles and
	// redundant re-expansion. Because BFS visits nodes in non-decreasing depth
	// order, the first encounter is always via the shortest path, enforcing
	// single-path-per-destination semantics.
	visited := make(map[string]bool)

	// Initialise the queue with the origin node at depth 0.
	queue := []bfsItem{
		{
			nodeID:    fromPrincipalID,
			depth:     0,
			pathNodes: []string{fromPrincipalID},
			pathEdges: []string{},
		},
	}

	for len(queue) > 0 {
		// Check for context cancellation before processing each item.
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Dequeue the front item (FIFO guarantees BFS level ordering).
		item := queue[0]
		queue = queue[1:]

		// Skip nodes already visited to handle cycles.
		if visited[item.nodeID] {
			continue
		}
		visited[item.nodeID] = true

		// If this node is a sensitive resource, record an attack path.
		// The origin node itself is never treated as a destination, even if it
		// happens to be marked sensitive, because an attacker is assumed to have
		// already compromised the starting principal.
		if item.nodeID != fromPrincipalID && e.sensitiveNodes[item.nodeID] {
			ap := buildAttackPath(e.snapshot.ID, fromPrincipalID, item.nodeID, item.depth, item.pathNodes, item.pathEdges, e)
			paths = append(paths, ap)
			// Continue traversal: there may be further sensitive resources reachable
			// through this one, but do not expand beyond maxHops from the origin.
		}

		// Do not enqueue neighbours if we have already reached the depth limit.
		if item.depth == maxHops {
			continue
		}

		// Expand outbound edges from the current node.
		for _, edge := range e.outbound[item.nodeID] {
			neighbour := edge.ToNodeID

			// Do not re-enqueue already-visited nodes.
			if visited[neighbour] {
				continue
			}

			// Build the extended path slices for the neighbour item.
			// We copy to avoid aliasing between queue items that share a common prefix.
			newPathNodes := make([]string, len(item.pathNodes)+1)
			copy(newPathNodes, item.pathNodes)
			newPathNodes[len(item.pathNodes)] = neighbour

			newPathEdges := make([]string, len(item.pathEdges)+1)
			copy(newPathEdges, item.pathEdges)
			newPathEdges[len(item.pathEdges)] = edge.ID

			queue = append(queue, bfsItem{
				nodeID:    neighbour,
				depth:     item.depth + 1,
				pathNodes: newPathNodes,
				pathEdges: newPathEdges,
			})
		}
	}

	// Sort attack paths by HopCount ascending, then by ID ascending for
	// fully deterministic output when multiple paths have the same hop count.
	sort.Slice(paths, func(i, j int) bool {
		if paths[i].HopCount != paths[j].HopCount {
			return paths[i].HopCount < paths[j].HopCount
		}
		return paths[i].ID < paths[j].ID
	})

	if paths == nil {
		paths = []*model.AttackPath{}
	}
	return paths, nil
}

// Neighbors returns all nodes directly reachable from nodeID via a single
// outbound edge whose Kind is contained in edgeKinds.
//
// Parameters:
//   - ctx: context for cancellation.
//   - nodeID: source node ID.
//   - edgeKinds: filter set; pass an empty slice to accept all edge kinds.
//
// Returns:
//   - []*model.Node, deduplicated; order is not guaranteed.
//
// Errors:
//   - ErrNotFound if nodeID does not exist in the graph.
func (e *Engine) Neighbors(ctx context.Context, nodeID string, edgeKinds []model.EdgeKind) ([]*model.Node, error) {
	if _, exists := e.nodes[nodeID]; !exists {
		return nil, fmt.Errorf("Neighbors: node %q: %w", nodeID, ErrNotFound)
	}

	// Build a lookup set for the requested edge kinds for O(1) membership tests.
	kindFilter := make(map[model.EdgeKind]bool, len(edgeKinds))
	for _, k := range edgeKinds {
		kindFilter[k] = true
	}
	acceptAll := len(edgeKinds) == 0

	// seen deduplicates result nodes when multiple edges lead to the same target.
	seen := make(map[string]bool)
	var result []*model.Node

	for _, edge := range e.outbound[nodeID] {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		if !acceptAll && !kindFilter[edge.Kind] {
			continue
		}
		if seen[edge.ToNodeID] {
			continue
		}
		seen[edge.ToNodeID] = true

		if n, ok := e.nodes[edge.ToNodeID]; ok {
			result = append(result, n)
		}
	}

	if result == nil {
		result = []*model.Node{}
	}
	return result, nil
}

// ShortestPath returns the minimum-hop path between two nodes using BFS.
//
// The implementation reuses the same BFS engine but short-circuits as soon as
// the destination node is first dequeued. Because BFS visits nodes in
// non-decreasing depth order, the first discovery is guaranteed to be the
// shortest path.
//
// Parameters:
//   - ctx: context for cancellation.
//   - from: source node ID.
//   - to: destination node ID.
//   - maxHops: maximum search depth; must be >= 1.
//
// Returns:
//   - *model.AttackPath describing the shortest path.
//
// Errors:
//   - ErrNotFound if from or to does not exist in the graph.
//   - ErrInvalidInput if maxHops < 1.
//   - ErrNoPath if no path from from to to exists within maxHops.
func (e *Engine) ShortestPath(ctx context.Context, from, to string, maxHops int) (*model.AttackPath, error) {
	if maxHops < 1 {
		return nil, fmt.Errorf("ShortestPath: maxHops must be >= 1: %w", ErrInvalidInput)
	}
	if _, exists := e.nodes[from]; !exists {
		return nil, fmt.Errorf("ShortestPath: source node %q: %w", from, ErrNotFound)
	}
	if _, exists := e.nodes[to]; !exists {
		return nil, fmt.Errorf("ShortestPath: destination node %q: %w", to, ErrNotFound)
	}

	visited := make(map[string]bool)

	queue := []bfsItem{
		{
			nodeID:    from,
			depth:     0,
			pathNodes: []string{from},
			pathEdges: []string{},
		},
	}

	for len(queue) > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		item := queue[0]
		queue = queue[1:]

		if visited[item.nodeID] {
			continue
		}
		visited[item.nodeID] = true

		// First encounter of the destination: construct and return the path.
		if item.nodeID == to {
			ap := buildAttackPath(e.snapshot.ID, from, to, item.depth, item.pathNodes, item.pathEdges, e)
			return ap, nil
		}

		if item.depth == maxHops {
			continue
		}

		for _, edge := range e.outbound[item.nodeID] {
			neighbour := edge.ToNodeID
			if visited[neighbour] {
				continue
			}

			newPathNodes := make([]string, len(item.pathNodes)+1)
			copy(newPathNodes, item.pathNodes)
			newPathNodes[len(item.pathNodes)] = neighbour

			newPathEdges := make([]string, len(item.pathEdges)+1)
			copy(newPathEdges, item.pathEdges)
			newPathEdges[len(item.pathEdges)] = edge.ID

			queue = append(queue, bfsItem{
				nodeID:    neighbour,
				depth:     item.depth + 1,
				pathNodes: newPathNodes,
				pathEdges: newPathEdges,
			})
		}
	}

	return nil, fmt.Errorf("ShortestPath: %s -> %s: %w", from, to, ErrNoPath)
}

// buildAttackPath constructs a model.AttackPath from raw BFS output.
//
// Parameters:
//   - snapshotID: the snapshot the path was discovered in.
//   - fromPrincipalID: the BFS origin node ID.
//   - toResourceID: the destination node ID (sensitive resource or ShortestPath target).
//   - hopCount: number of edges on the path.
//   - pathNodes: ordered slice of node IDs from origin to destination.
//   - pathEdges: ordered slice of edge IDs corresponding to each hop.
//   - e: the engine, used to resolve edge metadata for escalation detection.
//
// Returns:
//   - *model.AttackPath with all fields populated.
func buildAttackPath(snapshotID, fromPrincipalID, toResourceID string, hopCount int, pathNodes, pathEdges []string, e *Engine) *model.AttackPath {
	isEscalation := false
	for _, eid := range pathEdges {
		if edge, ok := e.edges[eid]; ok {
			if IsEscalationEdge(edge) {
				isEscalation = true
				break
			}
		}
	}

	// Derive a deterministic path ID from (from, to, hopCount, pathNodes) so that
	// two paths with the same endpoints but different intermediate nodes get distinct
	// IDs. json.Marshal is used for canonical, cross-platform serialisation.
	// The ID is truncated to 32 hex chars (16 bytes of sha256).
	pathKey, _ := json.Marshal([]any{fromPrincipalID, toResourceID, hopCount, pathNodes})
	h := sha256.Sum256(pathKey)
	id := fmt.Sprintf("path-%s", hex.EncodeToString(h[:16]))

	var chainClass model.ChainLengthClass
	switch {
	case hopCount <= 1:
		chainClass = model.ClassSimple
	case hopCount == 2:
		chainClass = model.ClassTwoHop
	default:
		chainClass = model.ClassMultiHop
	}

	// Copy path slices to avoid the caller retaining a reference to the BFS
	// internal buffers that may be mutated during further traversal.
	nodes := make([]string, len(pathNodes))
	copy(nodes, pathNodes)

	edgesCopy := make([]string, len(pathEdges))
	copy(edgesCopy, pathEdges)

	ap := &model.AttackPath{
		ID:                    id,
		SnapshotID:            snapshotID,
		FromPrincipalID:       fromPrincipalID,
		ToResourceID:          toResourceID,
		HopCount:              hopCount,
		PathNodes:             nodes,
		PathEdges:             edgesCopy,
		IsPrivilegeEscalation: isEscalation,
	}
	ap.ChainLengthClass = chainClass
	return ap
}
