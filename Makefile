# httpsec — auditor of HTTP security headers and TLS configuration
#
# `make build && make test && make lint` must be clean in a fresh clone.

BINARY      := httpsec
PKG         := github.com/dotMuny/httpsec
# A tag when there is one, otherwise a real version string. `git describe
# --always` would fall back to a bare commit hash, which shows up as
# "httpsec abcb854" in the banner of every report.
VERSION     ?= $(shell git describe --tags --dirty 2>/dev/null || echo 0.1.0-dev)
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE        ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS     := -s -w \
	-X $(PKG)/internal/version.Version=$(VERSION) \
	-X $(PKG)/internal/version.Commit=$(COMMIT) \
	-X $(PKG)/internal/version.Date=$(DATE)

# Coverage floor for internal/. The CSP package is held to a higher bar
# separately, because it is where the interesting logic lives.
COVERAGE_MIN     := 80
CSP_COVERAGE_MIN := 95

GO          ?= go
GOFLAGS     ?=
export CGO_ENABLED = 0

.PHONY: all build install test test-race cover cover-html lint fmt vet tidy \
        certs fixtures rubric-doc examples clean check help

all: build

## build: compile the binary into ./bin
build:
	$(GO) build $(GOFLAGS) -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/$(BINARY)

## install: install the binary into GOPATH/bin
install:
	$(GO) install $(GOFLAGS) -trimpath -ldflags "$(LDFLAGS)" ./cmd/$(BINARY)

## test: run the whole test suite
test:
	$(GO) test $(GOFLAGS) ./...

## test-race: run the suite under the race detector
test-race:
	CGO_ENABLED=1 $(GO) test $(GOFLAGS) -race ./...

## cover: run the suite with coverage and enforce the floors
cover:
	$(GO) test $(GOFLAGS) -coverprofile=coverage.out -covermode=atomic ./...
	@$(GO) tool cover -func=coverage.out | tail -1
	@$(MAKE) --no-print-directory cover-check DIR=internal/ MIN=$(COVERAGE_MIN)
	@$(MAKE) --no-print-directory cover-check DIR=internal/analyze/csp/ MIN=$(CSP_COVERAGE_MIN)

# cover-check computes statement coverage for one directory straight from the
# profile, which is the only number that is both exact and comparable across
# packages of different sizes.
.PHONY: cover-check
cover-check:
	@awk -F'[ ]' -v dir="$(DIR)" -v min="$(MIN)" ' \
		$$0 ~ /^mode:/ { next } \
		index($$1, dir) == 0 { next } \
		{ total += $$2; if ($$3 > 0) covered += $$2 } \
		END { \
			if (total == 0) { printf "%s: no statements found\n", dir; exit 1 } \
			pct = covered * 100 / total; \
			printf "%-26s %5.1f%% of %d statements (floor %s%%)\n", dir, pct, total, min; \
			exit (pct >= min + 0) ? 0 : 1 \
		}' coverage.out || { echo "coverage below the floor for $(DIR)"; exit 1; }

## cover-html: open the coverage report in a browser
cover-html: cover
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "wrote coverage.html"

## lint: run golangci-lint (including gosec)
lint:
	@command -v golangci-lint >/dev/null 2>&1 || { \
		echo "golangci-lint is not installed."; \
		echo "  go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
		exit 1; }
	golangci-lint run ./...

## fmt: format the tree
fmt:
	$(GO) fmt ./...
	gofmt -s -w .

## vet: run go vet
vet:
	$(GO) vet ./...

## tidy: tidy go.mod
tidy:
	$(GO) mod tidy

## rubric-doc: regenerate docs/rubric.md from the rubric data
rubric-doc:
	python3 scripts/gen-rubric-doc.py

## examples: regenerate docs/examples and the README images
examples: build
	./scripts/render-examples.sh

## certs: regenerate the TLS test certificates
certs:
	./scripts/gen-testdata-certs.sh

## fixtures: re-capture the observation fixtures (makes network requests)
fixtures: build
	./scripts/capture-fixtures.sh

## check: fmt, vet, test and lint in one go
check: fmt vet test lint

## clean: remove build output
clean:
	rm -rf bin dist coverage.out coverage.html

## help: list the targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## //' | awk -F': ' '{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'
