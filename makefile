.SUFFIXES:

SRCS := $(shell find ./cmd ./internal ./pkg -name '*.go') version.go VERSION

# The library lives in its own module under ./pkg, so per-module checks run in
# each. deadcode walks from the binary's main, so it runs in the root module
# only and ignores pkg/, where exported API the binary does not use is fine.
MODULES := . ./pkg

# Lint tools run via `go run`, pinned so a new release cannot fail the build
# unannounced.
STATICCHECK := honnef.co/go/tools/cmd/staticcheck@v0.8.2
DEADCODE    := golang.org/x/tools/cmd/deadcode@v0.48.0

help:  ## Show this help
	@awk 'BEGIN {FS = ":.*?## "} /^##@/ {printf "\n\033[1m%s\033[0m\n", substr($$0, 5)} /^[a-zA-Z0-9_.\/-]+:.*?## / {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

##@ build

.PHONY: build
build: ./bin/chisel-elftree  ## Build the binary into ./bin

./bin/chisel-elftree: $(SRCS) makefile go.mod go.sum pkg/go.mod pkg/go.sum
	mkdir -p ./bin
	go build -o ./bin/chisel-elftree ./cmd/chisel-elftree

.PHONY: install
install: ./bin/chisel-elftree  ## Symlink the binary into ~/.local/bin
	mkdir -p $(HOME)/.local/bin
	ln -sf "$(PWD)/bin/chisel-elftree" "$(HOME)/.local/bin/chisel-elftree"

##@ checks

.PHONY: test
test:  ## Run the unit tests with the race detector (real chisel ones skip without `chisel`)
	@for m in $(MODULES); do \
		(cd $$m && go test -race ./...) || exit 1; \
	done

.PHONY: e2e
e2e:  ## Run the end-to-end test (needs `chisel` + network; override CHISEL=..)
	CHISEL_ELFTREE_E2E=1 go test -tags e2e -count=1 -v ./e2e/...

.PHONY: lint
lint:  ## go vet + staticcheck + deadcode + gofmt check (no writes)
	@for m in $(MODULES); do \
		(cd $$m && go vet ./... && go run $(STATICCHECK) ./...) || exit 1; \
	done
	@out=$$(go run $(DEADCODE) -test ./... | grep -v '^pkg/'); \
	if [ -n "$$out" ]; then echo "Unreachable code:"; echo "$$out"; exit 1; fi
	@out=$$(gofmt -s -l ./cmd ./internal ./pkg ./e2e version.go); \
	if [ -n "$$out" ]; then echo "Unformatted files:"; echo "$$out"; exit 1; fi

.PHONY: format
format:  ## gofmt the tree in place
	gofmt -s -w ./cmd ./internal ./pkg ./e2e version.go

.PHONY: cover
cover:  ## Coverage profile + HTML report (cover.out, cover.html) per module
	@for m in $(MODULES); do \
		(cd $$m && go test -coverpkg=./... -coverprofile=cover.out -race ./... \
			&& go tool cover -func=cover.out \
			&& go tool cover -html=cover.out -o cover.html) || exit 1; \
	done

.PHONY: verify
verify: lint test  ## Pre-commit gate: lint + test
	@echo "All checks passed."

.PHONY: clean
clean:  ## Remove build artefacts
	rm -f ./bin/chisel-elftree
	rm -f ./cover.out ./cover.html ./pkg/cover.out ./pkg/cover.html
