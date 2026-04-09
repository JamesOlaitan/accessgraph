# syntax=docker/dockerfile:1.7

# Single-stage benchmark image for AccessGraph.
# Co-installs Go, two isolated Python 3.11 venvs, the
# AccessGraph binary, and IAMVulnerable cloned at the
# pinned commit. Self-contained — `docker run` produces
# the canonical benchmark execution environment.
FROM golang:1.26-bookworm@sha256:4f4ab2c90005e7e63cb631f0b4427f05422f241622ee3ec4727cc5febbf83e34

# System dependencies.
# python3 (3.11 on bookworm), python3-venv, python3-pip
# for the Prowler and Checkov venvs.
# git for the IAMVulnerable clone.
# ca-certificates for HTTPS in the clone step.
# build-essential is needed because pydantic-core and
# other transitive deps build C extensions on bookworm.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
         python3 \
         python3-venv \
         python3-pip \
         git \
         ca-certificates \
         build-essential \
    && rm -rf /var/lib/apt/lists/*

# Verify Python is 3.11.x as expected on bookworm.
RUN python3 --version | grep -E '^Python 3\.11\.' \
    || (echo "Expected Python 3.11.x, got $(python3 --version)" && exit 1)

# Two isolated Python virtual environments.
#
# Prowler 5.20.0 and Checkov 3.2.509 both pin boto3 to
# exact versions (boto3==1.40.61 and boto3==1.35.49
# respectively) and these pins are irreconcilable in a
# single virtual environment. Empirical verification:
# `pip install prowler==5.20.0 checkov==3.2.509` fails
# at resolution with "Cannot install checkov==3.2.509
# and prowler==5.20.0 because these package versions
# have conflicting dependencies." The exact-pin pattern
# is intentional on both upstream projects' side; they
# ship with specific tested AWS SDK versions for
# reproducibility.
#
# Both tools require pydantic v2 (>=2.0,<3.0); pydantic
# v1 is not used by either. An earlier project rationale
# incorrectly claimed pydantic v1/v2 was the conflict;
# that claim was based on Prowler 4.x (which did use
# pydantic v1 per upstream issue #5518) and was not
# updated when Prowler 5.20.0 was pinned.
#
# PMapper 1.1.5 has no boto3 pin or pydantic dependency
# and could live in either venv. It is placed in the
# Prowler venv as a matter of convention (the Prowler
# venv is the "AWS-tooling" venv); the choice is
# arbitrary and not load-bearing.
RUN python3 -m venv /opt/venv-prowler \
    && python3 -m venv /opt/venv-checkov

# Install Prowler + PMapper into Prowler venv.
COPY requirements-prowler.txt /tmp/requirements-prowler.txt
RUN /opt/venv-prowler/bin/pip install --no-cache-dir \
    --upgrade pip \
    && /opt/venv-prowler/bin/pip install --no-cache-dir \
       -r /tmp/requirements-prowler.txt

# Install Checkov into Checkov venv.
COPY requirements-checkov.txt /tmp/requirements-checkov.txt
RUN /opt/venv-checkov/bin/pip install --no-cache-dir \
    --upgrade pip \
    && /opt/venv-checkov/bin/pip install --no-cache-dir \
       -r /tmp/requirements-checkov.txt

# Patch PMapper 1.1.5 for Python 3.10+ compatibility.
#
# PMapper 1.1.5 (released January 2022, the latest published
# version) imports `Mapping` and `MutableMapping` directly
# from the `collections` module in
# principalmapper/util/case_insensitive_dict.py:34. These
# aliases were deprecated in Python 3.3 (moved to
# collections.abc) and removed in Python 3.10. The PMapper
# maintainer has not shipped a fix; see upstream issues
# nccgroup/PMapper#130, #131, #140 (all open).
#
# The patch is mechanical: it rewrites the single broken
# import to source `Mapping` and `MutableMapping` from
# collections.abc and `OrderedDict` from collections, which
# is the canonical Python 3.10+ form. No analysis logic is
# modified. The patched file is exclusively used by
# CaseInsensitiveDict, an internal helper class for IAM
# condition key matching, and the patch does not change
# CaseInsensitiveDict's behavior in any way.
#
# An audit of the entire PMapper 1.1.5 codebase confirmed
# this is the ONLY Python 3.10+ incompatibility (verified
# against collections aliases, inspect.getargspec,
# asyncio.coroutine, imp module, distutils, and
# datetime.utcnow). No other patches are required.
#
# See docs/benchmark_methodology.md §3.1 for the
# methodology-doc-level documentation of this patch.
RUN sed -i \
      's/^from collections import Mapping, MutableMapping, OrderedDict$/from collections.abc import Mapping, MutableMapping\nfrom collections import OrderedDict/' \
      /opt/venv-prowler/lib/python3.11/site-packages/principalmapper/util/case_insensitive_dict.py \
    && grep -q '^from collections.abc import Mapping, MutableMapping$' \
         /opt/venv-prowler/lib/python3.11/site-packages/principalmapper/util/case_insensitive_dict.py \
    && grep -q '^from collections import OrderedDict$' \
         /opt/venv-prowler/lib/python3.11/site-packages/principalmapper/util/case_insensitive_dict.py \
    && /opt/venv-prowler/bin/python -c \
         'from principalmapper.util.case_insensitive_dict import CaseInsensitiveDict; print("PMapper patch verified")'

# Verify each tool is reachable as expected.
RUN /opt/venv-prowler/bin/prowler --version \
    && /opt/venv-prowler/bin/pmapper -h > /dev/null \
    && /opt/venv-checkov/bin/checkov --version

# Clone IAMVulnerable at the pinned commit.
# Pinned to the exact SHA documented in
# benchmark_methodology.md §1.
ARG IAM_VULNERABLE_SHA=0f298666f9b7cfa01488b86912afdb211773188a
RUN git clone --depth 100 \
      https://github.com/BishopFox/iam-vulnerable.git \
      /opt/iam-vulnerable \
    && cd /opt/iam-vulnerable \
    && git checkout $IAM_VULNERABLE_SHA \
    && git rev-parse HEAD | grep -q "^${IAM_VULNERABLE_SHA}$" \
      || (echo "IAMVulnerable HEAD does not match pinned SHA" && exit 1)

# Build the AccessGraph binary from source.
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -mod=readonly -o /usr/local/bin/accessgraph ./cmd/accessgraph

# Verify the binary works.
RUN /usr/local/bin/accessgraph --help > /dev/null

# Entrypoint sets the four ACCESSGRAPH_* env vars and
# execs the user-provided command. Default command is
# `accessgraph --help` so `docker run <image>` does
# something useful out of the box.
ENV ACCESSGRAPH_PROWLER_PATH=/opt/venv-prowler/bin/prowler \
    ACCESSGRAPH_PMAPPER_PATH=/opt/venv-prowler/bin/pmapper \
    ACCESSGRAPH_CHECKOV_PATH=/opt/venv-checkov/bin/checkov \
    ACCESSGRAPH_IAMVULNERABLE_DIR=/opt/iam-vulnerable

WORKDIR /work
ENTRYPOINT ["/usr/local/bin/accessgraph"]
CMD ["--help"]
