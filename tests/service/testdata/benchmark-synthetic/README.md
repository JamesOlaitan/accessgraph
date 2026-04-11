# benchmark-synthetic

Hand-constructed minimal fixture for `tests/service/benchmark_test.go`.

Every field is chosen to exercise specific code paths in the benchmark
pipeline. This fixture is NOT a template for real scenario manifests;
real manifests follow `docs/benchmark_methodology.md` §4.2.

## Fixture constraints

- **Role name "admin"**: Required by the sensitivity heuristic's
  exact-match rule in `internal/analyzer/sensitivity.go`
  (`isAdminName("admin")` returns true). Renaming the role would
  cause the resource node to not be classified as sensitive, and the
  test would silently regress from TP to FN.

- **Non-wildcard Resource in policy statement**: The user's inline
  policy targets `arn:aws:iam::123456789012:role/admin` (not `"*"`).
  This causes the parser to create a Resource node for the role ARN
  through `ensureResource`, which the sensitivity classifier then
  marks as sensitive. A wildcard resource would skip Resource node
  creation and the BFS would not reach a terminal that
  `classifyDetectionInternal` can match.

- **UserPolicies field name**: The parser expects `UserPolicies`.
  The role equivalent is `RolePolicyList`. This asymmetry matches
  the AWS GetAccountAuthorizationDetails API response schema.

- **expected_attack_path terminal**: The last element
  (`arn:aws:iam::123456789012:role/admin`) must match the ARN of the
  Resource node that BFS reaches. `classifyDetectionInternal` performs
  an exact-match lookup of `path.ToResourceID` against
  `snapshot.Resources` ARNs.
