//go:build integration

package benchmark

// NewProwlerAdapter returns a ToolAdapter backed by prowlerAdapter.
// Exported for use in integration tests; not part of the stable API.
func NewProwlerAdapter() ToolAdapter { return &prowlerAdapter{} }

// NewPMapperAdapter returns a ToolAdapter backed by pmapperAdapter.
// Exported for use in integration tests; not part of the stable API.
func NewPMapperAdapter() ToolAdapter { return &pmapperAdapter{} }

// NewCheckovAdapter returns a ToolAdapter backed by checkovAdapter.
// Exported for use in integration tests; not part of the stable API.
func NewCheckovAdapter() ToolAdapter { return &checkovAdapter{} }

// NewSteampipeAdapter returns a ToolAdapter backed by steampipeAdapter.
// Exported for use in integration tests; not part of the stable API.
func NewSteampipeAdapter() ToolAdapter { return &steampipeAdapter{} }

// NewCloudSploitAdapter returns a ToolAdapter backed by cloudsploitAdapter.
// Exported for use in integration tests; not part of the stable API.
func NewCloudSploitAdapter() ToolAdapter { return &cloudsploitAdapter{} }
