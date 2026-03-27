// Package benchmark exercises the classifyDetectionInternal scoring function.
//
// Tests are in package benchmark (same package) so they can access the
// unexported classifyDetectionInternal function directly without indirection
// through the exported API.
package benchmark

import (
	"testing"

	"github.com/JamesOlaitan/accessgraph/internal/model"
)

// makeSnapshot builds a minimal Snapshot containing a single Resource with the
// given id and ARN. Additional resources can be appended after construction.
func makeSnapshot(resourceID, resourceARN string) *model.Snapshot {
	return &model.Snapshot{
		ID: "snap-test",
		Resources: []*model.Resource{
			{
				ID:  resourceID,
				ARN: resourceARN,
			},
		},
	}
}

// makeBlastRadius builds a BlastRadiusReport with a single path whose
// ToResourceID is set to the supplied value.
func makeBlastRadius(toResourceID string) *model.BlastRadiusReport {
	return &model.BlastRadiusReport{
		Paths: []*model.AttackPath{
			{
				ID:           "path-1",
				ToResourceID: toResourceID,
			},
		},
	}
}

// makeScenario builds a Scenario with the supplied expected attack path.
func makeScenario(expectedPath []string, isTN bool) *model.Scenario {
	return &model.Scenario{
		ID:                 "sc-test",
		ExpectedAttackPath: expectedPath,
		IsTrueNegative:     isTN,
	}
}

// TestAdminEquivalenceDefinition verifies the classifyDetectionInternal scoring
// function for all four outcome labels across the three admin-equivalence
// conditions and the true-negative cases.
func TestAdminEquivalenceDefinition(t *testing.T) {
	const (
		// adminPolicyARN is the ARN for an AWS managed AdministratorAccess policy,
		// representing admin-equivalence condition 1: AdministratorAccess attached.
		adminPolicyARN = "arn:aws:iam::aws:policy/AdministratorAccess"

		// iamStarRoleARN is a fictional IAM role ARN used as the terminal node for
		// admin-equivalence condition 2 (iam:* on *) and condition 3 (*:* on *).
		// The scoring function only checks whether the path's ToResourceID resolves
		// to the ARN stored in ExpectedAttackPath — it does not inspect permissions
		// itself, so the ARN value is arbitrary as long as it matches both sides.
		iamStarRoleARN = "arn:aws:iam::123456789012:role/iam-star-role"
		allStarRoleARN = "arn:aws:iam::123456789012:role/all-star-role"

		// nonAdminARN is a resource ARN that is NOT in any scenario's expected path.
		nonAdminARN = "arn:aws:s3:::not-admin-bucket"

		// principalARN is the starting principal used as path[0] in every scenario.
		principalARN = "arn:aws:iam::123456789012:user/attacker"
	)

	tests := []struct {
		name      string
		br        *model.BlastRadiusReport
		sc        *model.Scenario
		snapshot  *model.Snapshot
		wantLabel model.DetectionLabel
	}{
		// Condition 1: AdministratorAccess policy attached.
		// A path terminates at the AdministratorAccess managed-policy ARN, which
		// is stored as the last element of ExpectedAttackPath. The function should
		// return LabelTP because the resource ARN matches.
		{
			name: "TP_admin_policy_attached",
			br:   makeBlastRadius("res-admin-policy"),
			sc: makeScenario(
				[]string{principalARN, adminPolicyARN},
				false,
			),
			snapshot:  makeSnapshot("res-admin-policy", adminPolicyARN),
			wantLabel: model.LabelTP,
		},

		// Condition 2: iam:* on * permission.
		// The terminal resource is an IAM role that grants iam:* on *.
		// The scenario's ExpectedAttackPath ends at iamStarRoleARN, and the path
		// in the blast-radius report reaches a resource with that same ARN.
		{
			name: "TP_iam_star_permission",
			br:   makeBlastRadius("res-iam-star"),
			sc: makeScenario(
				[]string{principalARN, iamStarRoleARN},
				false,
			),
			snapshot:  makeSnapshot("res-iam-star", iamStarRoleARN),
			wantLabel: model.LabelTP,
		},

		// Condition 3: *:* on * permission.
		// The terminal resource grants all actions on all resources (*:* on *).
		// Same structural test as condition 2 but with a distinct ARN.
		{
			name: "TP_all_star_permission",
			br:   makeBlastRadius("res-all-star"),
			sc: makeScenario(
				[]string{principalARN, allStarRoleARN},
				false,
			),
			snapshot:  makeSnapshot("res-all-star", allStarRoleARN),
			wantLabel: model.LabelTP,
		},

		// Non-admin resource: FN.
		// The path terminates at a non-admin resource (an S3 bucket ARN) that does
		// NOT match the expected terminal ARN stored in the scenario. The function
		// must return LabelFN because no path reaches the expected terminal node.
		{
			name: "FN_non_admin_resource",
			br:   makeBlastRadius("res-non-admin"),
			sc: makeScenario(
				[]string{principalARN, adminPolicyARN},
				false,
			),
			// The snapshot maps "res-non-admin" to nonAdminARN, which does not equal adminPolicyARN.
			snapshot:  makeSnapshot("res-non-admin", nonAdminARN),
			wantLabel: model.LabelFN,
		},

		// No paths at all: FN.
		// The blast-radius report contains an empty Paths slice. The expected
		// terminal ARN exists in the snapshot but was never reached.
		{
			name: "FN_no_paths_found",
			br:   &model.BlastRadiusReport{Paths: nil},
			sc: makeScenario(
				[]string{principalARN, adminPolicyARN},
				false,
			),
			snapshot:  makeSnapshot("res-admin-policy", adminPolicyARN),
			wantLabel: model.LabelFN,
		},

		// True-negative scenario with no paths: TN.
		// The scenario is a true-negative (IsTrueNegative=true) and no paths were
		// found. The function must return LabelTN.
		{
			name: "TN_true_negative_no_paths",
			br:   &model.BlastRadiusReport{Paths: nil},
			sc: makeScenario(
				nil,  // TN scenarios have no ExpectedAttackPath
				true, // IsTrueNegative
			),
			snapshot:  &model.Snapshot{ID: "snap-tn"},
			wantLabel: model.LabelTN,
		},

		// True-negative scenario with paths found: FP.
		// The scenario is a true-negative but the tool discovered a path. The
		// function must return LabelFP (a false alarm on a clean environment).
		{
			name: "FP_true_negative_paths_found",
			br:   makeBlastRadius("res-some-resource"),
			sc: makeScenario(
				nil,  // TN scenarios have no ExpectedAttackPath
				true, // IsTrueNegative
			),
			snapshot:  makeSnapshot("res-some-resource", nonAdminARN),
			wantLabel: model.LabelFP,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyDetectionInternal(tc.br, tc.sc, tc.snapshot)
			if got != tc.wantLabel {
				t.Errorf("classifyDetectionInternal() = %q; want %q", got, tc.wantLabel)
			}
		})
	}
}
