.SUFFIXES:

SRCS := $(shell find ./cmd ./internal ./pkg -name '*.go')

# Lint tools run via `go run`, pinned so a new release cannot fail the build
# unannounced.
STATICCHECK := honnef.co/go/tools/cmd/staticcheck@v0.8.2

help:  ## Show this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_.\/-]+:.*?## / {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: build
build: ./bin/chisel-elftree  ## Build the binary into ./bin

./bin/chisel-elftree: $(SRCS) makefile go.mod go.sum
	mkdir -p ./bin
	go build -o ./bin/chisel-elftree ./cmd/chisel-elftree

.PHONY: test
test:  ## Run the unit tests (the real-chisel ones skip without chisel)
	go test -race ./...

.PHONY: lint
lint:  ## go vet + staticcheck + gofmt check (no writes)
	go vet ./...
	go run $(STATICCHECK) ./...
	@out=$$(gofmt -s -l ./cmd ./internal ./pkg); \
	if [ -n "$$out" ]; then echo "Unformatted files:"; echo "$$out"; exit 1; fi

.PHONY: format
format:  ## gofmt the tree in place
	gofmt -s -w ./cmd ./internal ./pkg

.PHONY: verify
verify: lint test  ## lint + test

.PHONY: clean
clean:  ## Remove build artefacts
	rm -f ./bin/chisel-elftree
