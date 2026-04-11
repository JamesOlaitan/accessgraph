#!/usr/bin/env bash
# capture_scenario.sh — deploy one IAMVulnerable scenario or TN environment
# to LocalStack, capture all four tool fixtures, and destroy the deployment.
#
# Two modes, dispatched by scenario name prefix:
#
#   Mode 1 (vulnerable): privesc* scenarios from the IAMVulnerable repo.
#     Copies <scenario>.tf + sre.tf + variables.tf to a temp dir, adds a
#     LocalStack provider override, and deploys. sre.tf is always included
#     per docs/benchmark_methodology.md §2.3.
#
#   Mode 2 (TN): tn-clean-NNN environments from terraform/tn-environments/.
#     Copies the self-contained TN module to a temp dir, adds a LocalStack
#     provider override, and deploys.
#
# Usage:
#   ./scripts/capture_scenario.sh <scenario-name>
#
# Examples:
#   ./scripts/capture_scenario.sh privesc1-CreateNewPolicyVersion
#   ./scripts/capture_scenario.sh tn-clean-001
#
# Produces (vulnerable mode):
#   fixtures/iamvulnerable/<scenario-name>/
#     ├── iam_export.json
#     ├── pmapper/000000000000/
#     ├── prowler.ocsf.json
#     └── checkov.json
#
# Produces (TN mode):
#   fixtures/iamvulnerable/<tn-name>/
#     ├── iam_export.json
#     ├── pmapper/000000000000/
#     ├── prowler.ocsf.json
#     └── checkov.json
#
# Prerequisites:
#   - docker
#   - terraform
#   - ./bin/accessgraph (run make build)
#   - accessgraph-benchmark:dev Docker image (run make docker-build)

set -euo pipefail

SCENARIO="${1:?Usage: $0 <scenario-name>}"

IAMV_COMMIT="0f298666f9b7cfa01488b86912afdb211773188a"
LOCALSTACK_IMAGE="localstack/localstack:3.8"
BENCHMARK_IMAGE="accessgraph-benchmark:dev"
ENDPOINT="http://localhost:4566"
CONTAINER_NAME="accessgraph-capture-localstack"
LOCALSTACK_ACCOUNT_ID="000000000000"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BINARY="${REPO_ROOT}/bin/accessgraph"
IAMV_CACHE="/tmp/iam-vulnerable-${IAMV_COMMIT}"

WORK_DIR=""
TF_INITIALIZED=false

# Cache Terraform provider downloads across runs.
export TF_PLUGIN_CACHE_DIR="${HOME}/.terraform.d/plugin-cache"
mkdir -p "$TF_PLUGIN_CACHE_DIR"

# Mode detection
if [[ "$SCENARIO" == tn-clean-* ]]; then
    MODE="tn"
    FIXTURE_DIR="${REPO_ROOT}/fixtures/iamvulnerable/${SCENARIO}"
else
    MODE="vulnerable"
    FIXTURE_DIR="${REPO_ROOT}/fixtures/iamvulnerable/${SCENARIO}"
fi

# Cleanup runs on EXIT, covering both success and failure paths.
cleanup() {
    echo "--- cleanup ---" >&2
    if [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]]; then
        if [[ "$TF_INITIALIZED" == "true" ]]; then
            echo "running terraform destroy..." >&2
            (
                cd "$WORK_DIR"
                if [[ "$MODE" == "vulnerable" ]]; then
                    terraform destroy -auto-approve -input=false \
                        -var="aws_assume_role_arn=arn:aws:iam::${LOCALSTACK_ACCOUNT_ID}:root" \
                        -var="aws_root_user=arn:aws:iam::${LOCALSTACK_ACCOUNT_ID}:root" \
                        2>&1 | tail -3 >&2
                else
                    terraform destroy -auto-approve -input=false \
                        2>&1 | tail -3 >&2
                fi
            ) || echo "WARNING: terraform destroy failed (resources may leak in LocalStack)" >&2
        fi
        rm -rf "$WORK_DIR"
    fi
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "--- precondition checks ---" >&2

for cmd in docker terraform; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "FAIL: $cmd not found on PATH" >&2
        exit 1
    fi
done

if [[ ! -x "$BINARY" ]]; then
    echo "FAIL: binary not found at $BINARY (run make build first)" >&2
    exit 1
fi

if ! docker image inspect "$BENCHMARK_IMAGE" &>/dev/null; then
    echo "FAIL: Docker image $BENCHMARK_IMAGE not found (run make docker-build first)" >&2
    exit 1
fi

# Clone or reuse IAMVulnerable checkout (vulnerable mode only).
if [[ "$MODE" == "vulnerable" ]]; then
    echo "--- cloning IAMVulnerable (cached) ---" >&2
    if [[ -d "$IAMV_CACHE" ]]; then
        CACHED_SHA=$(cd "$IAMV_CACHE" && git rev-parse HEAD 2>/dev/null || echo "")
        if [[ "$CACHED_SHA" != "$IAMV_COMMIT" ]]; then
            echo "cached clone at wrong commit ($CACHED_SHA), re-cloning..." >&2
            rm -rf "$IAMV_CACHE"
        else
            echo "using cached clone at ${IAMV_COMMIT:0:12}" >&2
        fi
    fi

    if [[ ! -d "$IAMV_CACHE" ]]; then
        git clone --quiet https://github.com/BishopFox/iam-vulnerable.git "$IAMV_CACHE"
        (cd "$IAMV_CACHE" && git checkout "$IAMV_COMMIT" --quiet)
        echo "cloned and checked out ${IAMV_COMMIT:0:12}" >&2
    fi

    PRIVESC_DIR="${IAMV_CACHE}/modules/free-resources/privesc-paths"
    SCENARIO_FILE="${PRIVESC_DIR}/${SCENARIO}.tf"
    if [[ ! -f "$SCENARIO_FILE" ]]; then
        echo "FAIL: scenario file not found: ${SCENARIO}.tf" >&2
        echo "Available scenarios:" >&2
        ls "${PRIVESC_DIR}/"*.tf \
            | xargs -n1 basename | sed 's/\.tf$//' \
            | grep -E '^privesc' | sort >&2
        exit 1
    fi
fi

if [[ "$MODE" == "tn" ]]; then
    TN_MODULE_DIR="${REPO_ROOT}/terraform/tn-environments/${SCENARIO}"
    if [[ ! -d "$TN_MODULE_DIR" ]]; then
        echo "FAIL: TN environment not found: ${TN_MODULE_DIR}" >&2
        echo "Available TN environments:" >&2
        ls -d "${REPO_ROOT}/terraform/tn-environments/tn-clean-"* \
            | xargs -n1 basename | sort >&2
        exit 1
    fi
fi

echo "--- starting LocalStack ---" >&2

docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
docker run -d \
    --name "$CONTAINER_NAME" \
    -p 4566:4566 \
    -e SERVICES=iam,sts,lambda \
    -v /var/run/docker.sock:/var/run/docker.sock \
    "$LOCALSTACK_IMAGE" >/dev/null

echo "waiting for LocalStack..." >&2
for i in $(seq 1 30); do
    if curl -sf "${ENDPOINT}/_localstack/health" >/dev/null 2>&1; then
        echo "LocalStack ready after ${i}s" >&2
        break
    fi
    if [[ "$i" -eq 30 ]]; then
        echo "FAIL: LocalStack did not become ready within 30s" >&2
        docker logs "$CONTAINER_NAME" >&2
        exit 1
    fi
    sleep 1
done

echo "--- preparing terraform working directory ---" >&2
WORK_DIR=$(mktemp -d)

if [[ "$MODE" == "vulnerable" ]]; then
    cp "${PRIVESC_DIR}/${SCENARIO}.tf" "$WORK_DIR/"
    cp "${PRIVESC_DIR}/sre.tf" "$WORK_DIR/"
    cp "${PRIVESC_DIR}/variables.tf" "$WORK_DIR/"

    # Provider config for LocalStack. Named *_override.tf so Terraform
    # merges it with the base configuration. For vulnerable mode, the
    # base has no provider block, so this adds one. The per-service
    # endpoint is handled by AWS_ENDPOINT_URL (set before terraform
    # init/apply), which the Terraform AWS provider respects as a
    # single-endpoint fallback for all services.
    cat > "${WORK_DIR}/localstack_override.tf" <<'TFEOF'
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  access_key                  = "test"
  secret_key                  = "test"
  region                      = "us-east-1"
  s3_use_path_style           = true
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
}
TFEOF

elif [[ "$MODE" == "tn" ]]; then
    cp "${TN_MODULE_DIR}/"*.tf "$WORK_DIR/"
    # The TN module lock files pin the latest provider version. The
    # LocalStack override below pins ~> 6.22 (see comment), so the
    # lock file is intentionally not copied to avoid a version
    # constraint conflict in the temporary working directory.

    # Override the provider block and pin the AWS provider to ~> 6.22.0
    # for LocalStack compatibility. Terraform AWS provider v6.23+
    # sends an S3 Control API request that LocalStack community
    # edition does not handle (LocalStack issue #13426), causing
    # CreateBucket operations to fail with MalformedXML. The
    # required_providers override deep-merges with the base
    # versions.tf; other providers (archive) are unaffected.
    # AWS_ENDPOINT_URL handles per-service routing;
    # s3_use_path_style is required for S3 bucket operations against
    # LocalStack's path-style addressing.
    cat > "${WORK_DIR}/localstack_override.tf" <<'TFEOF'
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.22.0"
    }
  }
}

provider "aws" {
  access_key                  = "test"
  secret_key                  = "test"
  region                      = "us-east-1"
  s3_use_path_style           = true
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
}
TFEOF
fi

echo "working directory contents:" >&2
ls "$WORK_DIR/" >&2

echo "--- terraform init ---" >&2
cd "$WORK_DIR"
export AWS_ENDPOINT_URL="$ENDPOINT"
terraform init -input=false >&2
TF_INITIALIZED=true

echo "--- terraform apply ---" >&2
if [[ "$MODE" == "vulnerable" ]]; then
    terraform apply -auto-approve -input=false \
        -var="aws_assume_role_arn=arn:aws:iam::${LOCALSTACK_ACCOUNT_ID}:root" \
        -var="aws_root_user=arn:aws:iam::${LOCALSTACK_ACCOUNT_ID}:root" \
        >&2
else
    terraform apply -auto-approve -input=false >&2
fi

echo "--- capturing fixtures ---" >&2
mkdir -p "$FIXTURE_DIR"

# 1. AccessGraph IAM export (host binary).
# Output path per docs/benchmark_methodology.md §7.1;
# must match internal/benchmark.IAMExportFilename.
echo "  [1/4] AccessGraph IAM export..." >&2
AWS_ACCESS_KEY_ID=test \
AWS_SECRET_ACCESS_KEY=test \
AWS_DEFAULT_REGION=us-east-1 \
ACCESSGRAPH_OFFLINE=false \
"$BINARY" export-iam \
    --endpoint-url "$ENDPOINT" \
    --region us-east-1 \
    --output "${FIXTURE_DIR}/iam_export.json"

# 2. PMapper graph create (runs in benchmark Docker image).
echo "  [2/4] PMapper graph create..." >&2
PMAPPER_TMP=$(mktemp -d)
docker run --rm \
    --network "container:${CONTAINER_NAME}" \
    -e PMAPPER_STORAGE=/storage \
    -e AWS_DEFAULT_REGION=us-east-1 \
    -e AWS_ACCESS_KEY_ID=test \
    -e AWS_SECRET_ACCESS_KEY=test \
    -v "${PMAPPER_TMP}:/storage" \
    --entrypoint /opt/venv-prowler/bin/pmapper \
    "$BENCHMARK_IMAGE" \
    graph create \
        --localstack-endpoint "$ENDPOINT" \
        --include-regions us-east-1 \
    >&2
mkdir -p "${FIXTURE_DIR}/pmapper"
if [[ -d "${PMAPPER_TMP}/${LOCALSTACK_ACCOUNT_ID}" ]]; then
    cp -r "${PMAPPER_TMP}/${LOCALSTACK_ACCOUNT_ID}" "${FIXTURE_DIR}/pmapper/"
else
    echo "WARNING: PMapper did not produce expected account directory" >&2
    echo "PMapper storage contents:" >&2
    find "$PMAPPER_TMP" -type f >&2
    cp -r "${PMAPPER_TMP}/"* "${FIXTURE_DIR}/pmapper/" 2>/dev/null || true
fi
rm -rf "$PMAPPER_TMP"

# 3. Prowler (runs in benchmark Docker image).
echo "  [3/4] Prowler scan..." >&2
PROWLER_TMP=$(mktemp -d)
set +e
docker run --rm \
    --network "container:${CONTAINER_NAME}" \
    -e AWS_ENDPOINT_URL="$ENDPOINT" \
    -e AWS_ACCESS_KEY_ID=test \
    -e AWS_SECRET_ACCESS_KEY=test \
    -e AWS_DEFAULT_REGION=us-east-1 \
    -v "${PROWLER_TMP}:/output" \
    --entrypoint /opt/venv-prowler/bin/prowler \
    "$BENCHMARK_IMAGE" \
    aws --output-formats json-ocsf --output-directory /output \
    >&2
PROWLER_EXIT=$?
set -e
# Exit 0 = no findings, exit 3 = findings found; both are success.
if [[ "$PROWLER_EXIT" -ne 0 && "$PROWLER_EXIT" -ne 3 ]]; then
    echo "FAIL: Prowler exited with code $PROWLER_EXIT" >&2
    exit 1
fi
OCSF_FILE=$(find "$PROWLER_TMP" -name "*.ocsf.json" -type f | head -1)
if [[ -z "$OCSF_FILE" ]]; then
    echo "FAIL: Prowler did not produce an .ocsf.json output file" >&2
    echo "Prowler output directory contents:" >&2
    find "$PROWLER_TMP" -type f >&2
    exit 1
fi
cp "$OCSF_FILE" "${FIXTURE_DIR}/prowler.ocsf.json"
rm -rf "$PROWLER_TMP"

# 4. Checkov scans Terraform source, not the deployed state.
echo "  [4/4] Checkov scan..." >&2
set +e
docker run --rm \
    -v "${WORK_DIR}:/code:ro" \
    --entrypoint /opt/venv-checkov/bin/checkov \
    "$BENCHMARK_IMAGE" \
    -d /code --framework terraform --output json \
    > "${FIXTURE_DIR}/checkov.json" 2>&2
CHECKOV_EXIT=$?
set -e
# Exit 1 = check failures found (expected); exit 0 = all checks passed.
if [[ "$CHECKOV_EXIT" -ne 0 && "$CHECKOV_EXIT" -ne 1 ]]; then
    echo "FAIL: Checkov exited with code $CHECKOV_EXIT" >&2
    exit 1
fi

echo "" >&2
echo "--- capture complete ---" >&2
echo "${FIXTURE_DIR}/" >&2
for f in iam_export.json prowler.ocsf.json checkov.json; do
    if [[ -f "${FIXTURE_DIR}/${f}" ]]; then
        SIZE=$(du -h "${FIXTURE_DIR}/${f}" | cut -f1)
        echo "  ${f}  (${SIZE})" >&2
    else
        echo "  ${f}  MISSING" >&2
    fi
done
if [[ -d "${FIXTURE_DIR}/pmapper" ]]; then
    SIZE=$(du -sh "${FIXTURE_DIR}/pmapper" | cut -f1)
    echo "  pmapper/  (${SIZE})" >&2
else
    echo "  pmapper/  MISSING" >&2
fi

ENTITY_COUNT=$(python3 -c "
import json, sys
data = json.load(open(sys.argv[1]))
users = len(data.get('users', []))
roles = len(data.get('roles', []))
groups = len(data.get('groups', []))
print(f'{users} users, {roles} roles, {groups} groups')
" "${FIXTURE_DIR}/iam_export.json" 2>/dev/null || echo "parse error")
echo "  iam_export.json entities: ${ENTITY_COUNT}" >&2

echo "" >&2
echo "SUCCESS: ${SCENARIO} captured to ${FIXTURE_DIR}" >&2
