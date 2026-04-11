#!/usr/bin/env bash
# smoke_export_iam.sh — end-to-end smoke test for the export-iam subcommand
# against LocalStack. Requires Docker (for LocalStack) and awslocal (from
# localstack CLI).
#
# Usage:
#   ./scripts/smoke_export_iam.sh
#   make smoke-export-iam
#
# Exit code 0 on success; non-zero with diagnostic output on failure.

set -euo pipefail

LOCALSTACK_IMAGE="localstack/localstack:3.8"
CONTAINER_NAME="accessgraph-smoke-localstack"
ENDPOINT="http://localhost:4566"
BINARY="./bin/accessgraph"
OUTPUT="/tmp/smoke-export-iam.json"

cleanup() {
    echo "--- cleanup ---"
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
    rm -f "$OUTPUT"
}
trap cleanup EXIT

# -------------------------------------------------------------------
# Step 1: Start LocalStack
# -------------------------------------------------------------------
echo "--- starting LocalStack ---"

if ! command -v docker &>/dev/null; then
    echo "FAIL: docker not found on PATH"
    exit 1
fi

docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
docker run -d \
    --name "$CONTAINER_NAME" \
    -p 4566:4566 \
    -e SERVICES=iam,sts \
    "$LOCALSTACK_IMAGE" >/dev/null

echo "waiting for LocalStack to be ready..."
for i in $(seq 1 30); do
    if curl -sf "$ENDPOINT/_localstack/health" >/dev/null 2>&1; then
        echo "LocalStack ready after ${i}s"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "FAIL: LocalStack did not become ready within 30s"
        docker logs "$CONTAINER_NAME"
        exit 1
    fi
    sleep 1
done

# -------------------------------------------------------------------
# Step 2: Create a small IAM scenario via AWS CLI
# -------------------------------------------------------------------
echo "--- creating IAM scenario ---"

export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1

aws --endpoint-url "$ENDPOINT" iam create-user --user-name smoke-user >/dev/null
aws --endpoint-url "$ENDPOINT" iam create-group --group-name smoke-group >/dev/null
aws --endpoint-url "$ENDPOINT" iam add-user-to-group --user-name smoke-user --group-name smoke-group >/dev/null

aws --endpoint-url "$ENDPOINT" iam create-policy \
    --policy-name smoke-policy \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}' \
    >/dev/null

TRUST_POLICY='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
aws --endpoint-url "$ENDPOINT" iam create-role \
    --role-name smoke-role \
    --assume-role-policy-document "$TRUST_POLICY" \
    >/dev/null

echo "IAM scenario created: 1 user, 1 role, 1 group, 1 policy"

# -------------------------------------------------------------------
# Step 3: Run accessgraph export-iam
# -------------------------------------------------------------------
echo "--- running export-iam ---"

if [ ! -x "$BINARY" ]; then
    echo "FAIL: binary not found at $BINARY (run make build first)"
    exit 1
fi

"$BINARY" export-iam \
    --endpoint-url "$ENDPOINT" \
    --region us-east-1 \
    --output "$OUTPUT" 2>&1

if [ ! -s "$OUTPUT" ]; then
    echo "FAIL: output file is empty"
    exit 1
fi

# -------------------------------------------------------------------
# Step 4: Validate the output JSON
# -------------------------------------------------------------------
echo "--- validating output ---"

if ! python3 -c "import json, sys; json.load(open(sys.argv[1]))" "$OUTPUT" 2>/dev/null; then
    echo "FAIL: output is not valid JSON"
    cat "$OUTPUT"
    exit 1
fi

check_name() {
    local key="$1"
    local name="$2"
    if ! python3 -c "
import json, sys
data = json.load(open(sys.argv[1]))
items = data.get('$key', [])
names = [item.get('UserName') or item.get('RoleName') or item.get('GroupName') or item.get('PolicyName') for item in items]
if '$name' not in names:
    print(f'FAIL: $name not found in $key, got: {names}')
    sys.exit(1)
" "$OUTPUT"; then
        exit 1
    fi
}

check_name "users" "smoke-user"
check_name "roles" "smoke-role"
check_name "groups" "smoke-group"
check_name "policies" "smoke-policy"

echo "--- smoke test PASSED ---"
