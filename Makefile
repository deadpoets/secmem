# secmem — developer tasks. Everything here uses the standard Go toolchain;
# the extra analyzers (golangci-lint, staticcheck, govulncheck) are optional
# and only required by the `lint` and `vuln` targets.
#
# Three Go modules live in this repo (core at the root, secmem-crypto/, and the
# secmem-lint analyzer). Go's ./... never crosses module boundaries — even under
# a go.work — so every module-scoped target loops over MODULES to match what CI
# enforces. `dogfood` builds the analyzer and runs it over the two library modules.

GO           ?= go
MODULES      ?= . secmem-crypto secmem-lint
FUZZ_MODULES ?= . secmem-crypto
COVER        ?= coverage.txt

.PHONY: all
all: fmt vet test

.PHONY: test
test:
	@for m in $(MODULES); do (cd $$m && $(GO) test -race ./...) || exit 1; done

.PHONY: fmt
fmt:
	@for m in $(MODULES); do (cd $$m && $(GO) fmt ./...) || exit 1; done
	gofmt -s -l .

.PHONY: vet
vet:
	@for m in $(MODULES); do (cd $$m && $(GO) vet ./...) || exit 1; done

.PHONY: lint
lint:
	@for m in $(MODULES); do (cd $$m && golangci-lint run && staticcheck ./...) || exit 1; done

# dogfood builds the secmem-lint analyzer and runs it (via go vet -vettool) over
# the two library modules — the same check CI's secmem-lint job enforces.
.PHONY: dogfood
dogfood:
	@tool=$$(mktemp); trap 'rm -f "$$tool"' EXIT; \
	(cd secmem-lint && $(GO) build -o "$$tool" ./cmd/secmem-lint) && \
	for m in . secmem-crypto; do (cd $$m && $(GO) vet -vettool="$$tool" ./...) || exit 1; done

.PHONY: vuln
vuln:
	@for m in $(MODULES); do (cd $$m && govulncheck ./...) || exit 1; done

.PHONY: fuzz
fuzz:
	@for m in $(FUZZ_MODULES); do (cd $$m && $(GO) test -run '^$$' -fuzz . -fuzztime 30s ./...) || exit 1; done

.PHONY: cover
cover:
	@for m in $(MODULES); do (cd $$m && $(GO) test -race -coverprofile=$(COVER) ./... && $(GO) tool cover -func=$(COVER)) || exit 1; done

.PHONY: tidy
tidy:
	@for m in $(MODULES); do (cd $$m && $(GO) mod tidy && $(GO) mod verify) || exit 1; done

.PHONY: clean
clean:
	@for m in $(MODULES); do (cd $$m && $(GO) clean && rm -f $(COVER) coverage.html) || exit 1; done
