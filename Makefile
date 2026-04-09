BINARY   := accessgraph
MODULE   := github.com/JamesOlaitan/accessgraph
CMD_DIR  := ./cmd/accessgraph
BIN_DIR  := bin

# Version is the git tag or commit hash used for reproducibility labeling.
VERSION  := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS  := -ldflags "-X $(MODULE)/cmd/accessgraph/commands.Version=$(VERSION)"

.PHONY: all build test test-integration lint fmt vet clean demo tidy audit docker-build docker-up docker-down

all: build

## build: Compile the accessgraph binary into bin/.
build:
	@mkdir -p $(BIN_DIR)
	go build $(LDFLAGS) -o $(BIN_DIR)/$(BINARY) $(CMD_DIR)

## test: Run unit tests (requires only Go; no external tools or OPA server needed).
test:
	go test -race -count=1 -timeout 120s ./...

## test-integration: Run the full benchmark suite including external tool invocations.
## Requires Prowler, PMapper, and Checkov to be installed and on PATH.
test-integration:
	go test -race -count=1 -timeout 600s -tags integration ./...

## lint: Run golangci-lint over all packages.
lint:
	golangci-lint run ./...

## fmt: Format all Go source files with gofmt.
fmt:
	gofmt -s -w .

## vet: Run go vet over all packages.
vet:
	go vet ./...

## tidy: Tidy and verify the module dependency graph.
tidy:
	go mod tidy
	go mod verify

## clean: Remove compiled artifacts.
clean:
	rm -rf $(BIN_DIR)
	find . -name "*.test" -delete
	find . -name "coverage.txt" -delete

## demo: Run a self-contained demo against the bundled sample data.
## Works from a clean clone with no environment variables set.
demo: build
	@echo "--- AccessGraph demo: ingesting sample IAM snapshot ---"
	./$(BIN_DIR)/$(BINARY) ingest --source sample/aws/demo_policy.json --label demo
	@echo ""
	@echo "--- Blast-radius analysis from sample compromised principal ---"
	./$(BIN_DIR)/$(BINARY) analyze --label demo --from arn:aws:iam::123456789012:user/dev-user
	@echo ""
	@echo "--- JSON output ---"
	./$(BIN_DIR)/$(BINARY) analyze --label demo --from arn:aws:iam::123456789012:user/dev-user --output json

## audit: Run architectural fitness checks (layer deps, interface assertions, MetricFloat, JSON tags).
audit:
	bash scripts/audit.sh

docker-build:
	docker build -t accessgraph-benchmark:dev .

docker-up:
	docker compose up -d

docker-down:
	docker compose down

## help: Print this message.
help:
	@grep -E '^## ' Makefile | sed 's/## //'
