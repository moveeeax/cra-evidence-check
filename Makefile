BINARY := bin/cra-evidence-check
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X github.com/moveeeax/cra-evidence-check/internal/cli.Version=$(VERSION)

.PHONY: all build test fmt vet check demo clean

all: check build

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/cra-evidence-check

test:
	go test -race -count=1 ./...

fmt:
	gofmt -w .

vet:
	go vet ./...

check: vet test
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then echo "not gofmt-clean:"; echo "$$unformatted"; exit 1; fi

# Run the tool against the bundled fixtures. The second run is expected to
# report findings, so its exit code 1 is not a build failure.
demo: build
	$(BINARY) scan --repo testdata/repo/compliant --release-dir testdata/release/complete
	-$(BINARY) scan --repo testdata/repo/gaps --release-dir testdata/release/uncovered

clean:
	rm -rf bin
