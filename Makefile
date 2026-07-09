# secmem — developer tasks. Everything here uses the standard Go toolchain;
# the extra analyzers (golangci-lint, staticcheck, govulncheck) are optional
# and only required by the `lint` and `vuln` targets.

GO      ?= go
PKGS    ?= ./...
COVER   ?= coverage.txt

.PHONY: all
all: fmt vet test

.PHONY: test
test:
	$(GO) test -race $(PKGS)

.PHONY: fmt
fmt:
	$(GO) fmt $(PKGS)
	gofmt -s -l .

.PHONY: vet
vet:
	$(GO) vet $(PKGS)

.PHONY: lint
lint:
	golangci-lint run
	staticcheck $(PKGS)

.PHONY: vuln
vuln:
	govulncheck $(PKGS)

.PHONY: fuzz
fuzz:
	$(GO) test -run '^$$' -fuzz . -fuzztime 30s $(PKGS)

.PHONY: cover
cover:
	$(GO) test -race -coverprofile=$(COVER) $(PKGS)
	$(GO) tool cover -func=$(COVER)

.PHONY: tidy
tidy:
	$(GO) mod tidy
	$(GO) mod verify

.PHONY: clean
clean:
	$(GO) clean
	rm -f $(COVER) coverage.html
