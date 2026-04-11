// Package iamexport exports an AWS account's IAM configuration as JSON in the
// format consumed by AccessGraph's parser (internal/parser/aws_iam.go).
package iamexport

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// IAMAPI is the subset of the IAM client API used by the exporter.
type IAMAPI interface {
	GetAccountAuthorizationDetails(
		ctx context.Context,
		params *iam.GetAccountAuthorizationDetailsInput,
		optFns ...func(*iam.Options),
	) (*iam.GetAccountAuthorizationDetailsOutput, error)
}

// STSAPI is the subset of the STS client API used by the exporter.
type STSAPI interface {
	GetCallerIdentity(
		ctx context.Context,
		params *sts.GetCallerIdentityInput,
		optFns ...func(*sts.Options),
	) (*sts.GetCallerIdentityOutput, error)
}

// Stats holds counts of exported IAM entities.
type Stats struct {
	Users    int
	Roles    int
	Groups   int
	Policies int
}

// Exporter exports an AWS account's IAM configuration as JSON.
type Exporter struct {
	IAM IAMAPI
	STS STSAPI
}

// Export fetches the full IAM configuration and writes JSON to w in the format
// expected by AccessGraph's parser. The output contains users, roles, groups,
// and managed policies with all policy documents decoded from URL encoding.
func (e *Exporter) Export(ctx context.Context, w io.Writer) (Stats, error) {
	identity, err := e.STS.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return Stats{}, fmt.Errorf("get caller identity: %w", err)
	}
	accountID := aws.ToString(identity.Account)

	var (
		users    []iamtypes.UserDetail
		roles    []iamtypes.RoleDetail
		groups   []iamtypes.GroupDetail
		policies []iamtypes.ManagedPolicyDetail
	)

	input := &iam.GetAccountAuthorizationDetailsInput{
		Filter: []iamtypes.EntityType{
			iamtypes.EntityTypeUser,
			iamtypes.EntityTypeRole,
			iamtypes.EntityTypeGroup,
			iamtypes.EntityTypeLocalManagedPolicy,
			iamtypes.EntityTypeAWSManagedPolicy,
		},
	}

	for {
		out, err := e.IAM.GetAccountAuthorizationDetails(ctx, input)
		if err != nil {
			return Stats{}, fmt.Errorf("get account authorization details: %w", err)
		}

		users = append(users, out.UserDetailList...)
		roles = append(roles, out.RoleDetailList...)
		groups = append(groups, out.GroupDetailList...)
		policies = append(policies, out.Policies...)

		if !out.IsTruncated || out.Marker == nil {
			break
		}
		input.Marker = out.Marker
	}

	export, err := buildExport(accountID, users, roles, groups, policies)
	if err != nil {
		return Stats{}, fmt.Errorf("build export: %w", err)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(export); err != nil {
		return Stats{}, fmt.Errorf("encode JSON: %w", err)
	}

	return Stats{
		Users:    len(users),
		Roles:    len(roles),
		Groups:   len(groups),
		Policies: len(policies),
	}, nil
}

// Output types matching internal/parser/aws_iam.go's input schema.
// Top-level keys are lowercase; nested fields are PascalCase.

type exportOutput struct {
	AccountID string         `json:"account_id"`
	Users     []exportUser   `json:"users"`
	Roles     []exportRole   `json:"roles"`
	Groups    []exportGroup  `json:"groups"`
	Policies  []exportPolicy `json:"policies"`
}

type exportUser struct {
	UserName                string           `json:"UserName"`
	UserID                  string           `json:"UserId"`
	ARN                     string           `json:"Arn"`
	AttachedManagedPolicies []exportAttached `json:"AttachedManagedPolicies"`
	UserPolicies            []exportInline   `json:"UserPolicies"`
	GroupList               []string         `json:"GroupList"`
}

type exportRole struct {
	RoleName                 string           `json:"RoleName"`
	RoleID                   string           `json:"RoleId"`
	ARN                      string           `json:"Arn"`
	AssumeRolePolicyDocument json.RawMessage  `json:"AssumeRolePolicyDocument,omitempty"`
	AttachedManagedPolicies  []exportAttached `json:"AttachedManagedPolicies"`
	RolePolicyList           []exportInline   `json:"RolePolicyList"`
}

type exportGroup struct {
	GroupName               string           `json:"GroupName"`
	GroupID                 string           `json:"GroupId"`
	ARN                     string           `json:"Arn"`
	AttachedManagedPolicies []exportAttached `json:"AttachedManagedPolicies"`
	GroupPolicyList         []exportInline   `json:"GroupPolicyList"`
}

type exportPolicy struct {
	PolicyName     string          `json:"PolicyName"`
	PolicyARN      string          `json:"PolicyArn"`
	PolicyDocument json.RawMessage `json:"PolicyDocument,omitempty"`
}

type exportAttached struct {
	PolicyARN  string `json:"PolicyArn"`
	PolicyName string `json:"PolicyName"`
}

type exportInline struct {
	PolicyName     string          `json:"PolicyName"`
	PolicyDocument json.RawMessage `json:"PolicyDocument,omitempty"`
}

func buildExport(
	accountID string,
	users []iamtypes.UserDetail,
	roles []iamtypes.RoleDetail,
	groups []iamtypes.GroupDetail,
	policies []iamtypes.ManagedPolicyDetail,
) (*exportOutput, error) {
	out := &exportOutput{
		AccountID: accountID,
		Users:     make([]exportUser, 0, len(users)),
		Roles:     make([]exportRole, 0, len(roles)),
		Groups:    make([]exportGroup, 0, len(groups)),
		Policies:  make([]exportPolicy, 0, len(policies)),
	}

	for _, u := range users {
		eu, err := convertUser(u)
		if err != nil {
			return nil, fmt.Errorf("convert user %s: %w", aws.ToString(u.UserName), err)
		}
		out.Users = append(out.Users, eu)
	}

	for _, r := range roles {
		er, err := convertRole(r)
		if err != nil {
			return nil, fmt.Errorf("convert role %s: %w", aws.ToString(r.RoleName), err)
		}
		out.Roles = append(out.Roles, er)
	}

	for _, g := range groups {
		eg, err := convertGroup(g)
		if err != nil {
			return nil, fmt.Errorf("convert group %s: %w", aws.ToString(g.GroupName), err)
		}
		out.Groups = append(out.Groups, eg)
	}

	for _, p := range policies {
		ep, err := convertPolicy(p)
		if err != nil {
			return nil, fmt.Errorf("convert policy %s: %w", aws.ToString(p.PolicyName), err)
		}
		out.Policies = append(out.Policies, ep)
	}

	return out, nil
}

func convertUser(u iamtypes.UserDetail) (exportUser, error) {
	groups := u.GroupList
	if groups == nil {
		groups = []string{}
	}

	inlines, err := convertInlinePolicies(u.UserPolicyList)
	if err != nil {
		return exportUser{}, err
	}

	return exportUser{
		UserName:                aws.ToString(u.UserName),
		UserID:                  aws.ToString(u.UserId),
		ARN:                     aws.ToString(u.Arn),
		AttachedManagedPolicies: convertAttached(u.AttachedManagedPolicies),
		UserPolicies:            inlines,
		GroupList:               groups,
	}, nil
}

func convertRole(r iamtypes.RoleDetail) (exportRole, error) {
	er := exportRole{
		RoleName:                aws.ToString(r.RoleName),
		RoleID:                  aws.ToString(r.RoleId),
		ARN:                     aws.ToString(r.Arn),
		AttachedManagedPolicies: convertAttached(r.AttachedManagedPolicies),
	}

	if r.AssumeRolePolicyDocument != nil {
		doc, err := decodePolicyDocument(*r.AssumeRolePolicyDocument)
		if err != nil {
			return exportRole{}, fmt.Errorf("decode assume role policy: %w", err)
		}
		er.AssumeRolePolicyDocument = doc
	}

	inlines, err := convertInlinePolicies(r.RolePolicyList)
	if err != nil {
		return exportRole{}, err
	}
	er.RolePolicyList = inlines

	return er, nil
}

func convertGroup(g iamtypes.GroupDetail) (exportGroup, error) {
	inlines, err := convertInlinePolicies(g.GroupPolicyList)
	if err != nil {
		return exportGroup{}, err
	}

	return exportGroup{
		GroupName:               aws.ToString(g.GroupName),
		GroupID:                 aws.ToString(g.GroupId),
		ARN:                     aws.ToString(g.Arn),
		AttachedManagedPolicies: convertAttached(g.AttachedManagedPolicies),
		GroupPolicyList:         inlines,
	}, nil
}

func convertPolicy(p iamtypes.ManagedPolicyDetail) (exportPolicy, error) {
	ep := exportPolicy{
		PolicyName: aws.ToString(p.PolicyName),
		PolicyARN:  aws.ToString(p.Arn),
	}

	for _, v := range p.PolicyVersionList {
		if v.IsDefaultVersion && v.Document != nil {
			doc, err := decodePolicyDocument(*v.Document)
			if err != nil {
				return exportPolicy{}, fmt.Errorf("decode policy document: %w", err)
			}
			ep.PolicyDocument = doc
			break
		}
	}

	return ep, nil
}

func convertAttached(attached []iamtypes.AttachedPolicy) []exportAttached {
	result := make([]exportAttached, len(attached))
	for i, a := range attached {
		result[i] = exportAttached{
			PolicyARN:  aws.ToString(a.PolicyArn),
			PolicyName: aws.ToString(a.PolicyName),
		}
	}
	return result
}

func convertInlinePolicies(inlines []iamtypes.PolicyDetail) ([]exportInline, error) {
	result := make([]exportInline, 0, len(inlines))
	for _, p := range inlines {
		ei := exportInline{
			PolicyName: aws.ToString(p.PolicyName),
		}
		if p.PolicyDocument != nil {
			doc, err := decodePolicyDocument(*p.PolicyDocument)
			if err != nil {
				return nil, fmt.Errorf("decode inline policy %s: %w", aws.ToString(p.PolicyName), err)
			}
			ei.PolicyDocument = doc
		}
		result = append(result, ei)
	}
	return result, nil
}

// decodePolicyDocument decodes an AWS policy document string, which may be
// URL-encoded (as returned by the IAM API) or already plain JSON (as returned
// by some mock/local endpoints like LocalStack).
func decodePolicyDocument(s string) (json.RawMessage, error) {
	if s == "" {
		return nil, nil
	}

	if json.Valid([]byte(s)) {
		return json.RawMessage(s), nil
	}

	decoded, err := url.QueryUnescape(s)
	if err != nil {
		return nil, fmt.Errorf("url-decode policy document: %w", err)
	}

	if !json.Valid([]byte(decoded)) {
		return nil, fmt.Errorf("policy document is not valid JSON after URL decoding")
	}

	return json.RawMessage(decoded), nil
}
