MODULE   := github.com/0xc0de1ab/vdexcli
BIN      := vdexcli
VERSION  := $(shell grep 'var CLIVersion' internal/model/constants.go | sed 's/.*"\(.*\)"/\1/')
COMMIT   := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

GOOS     ?= $(shell go env GOOS)
GOARCH   ?= $(shell go env GOARCH)
VARIANT  ?= release

BUILD_DIR := build/$(GOOS)-$(GOARCH)/$(VARIANT)

LDFLAGS_RELEASE := -s -w -X '$(MODULE)/internal/model.CLIVersion=$(VERSION)' -X '$(MODULE)/internal/model.GitCommit=$(COMMIT)'
LDFLAGS_DEBUG   := -X '$(MODULE)/internal/model.CLIVersion=$(VERSION)' -X '$(MODULE)/internal/model.GitCommit=$(COMMIT)'
LDFLAGS         := $(if $(filter release,$(VARIANT)),$(LDFLAGS_RELEASE),$(LDFLAGS_DEBUG))

GCFLAGS_DEBUG   := -N -l
GCFLAGS         := $(if $(filter debug,$(VARIANT)),$(GCFLAGS_DEBUG),)

GO_BUILD := CGO_ENABLED=0 go build \
	-ldflags "$(LDFLAGS)" \
	$(if $(GCFLAGS),-gcflags "$(GCFLAGS)",) \
	-o $(BUILD_DIR)/$(BIN)

.PHONY: all build test lint clean fmt vet

all: fmt vet lint test build

build:
	@mkdir -p $(BUILD_DIR)
	$(GO_BUILD) .
	@echo "built $(BUILD_DIR)/$(BIN) ($(GOOS)/$(GOARCH)/$(VARIANT) v$(VERSION))"

test:
	go test -v -count=1 ./...

lint:
	@which golangci-lint > /dev/null 2>&1 && golangci-lint run ./... || echo "golangci-lint not installed, skipping"

fmt:
	gofmt -w .

vet:
	go vet ./...

cross-build:
	@for os in linux darwin windows; do \
		for arch in amd64 arm64; do \
			if [ "$$os" = "windows" ] && [ "$$arch" = "arm64" ]; then continue; fi; \
			GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build -o /dev/null . && \
				echo "  $$os/$$arch OK" || echo "  $$os/$$arch FAIL"; \
		done; \
	done

clean:
	rm -rf build/
	rm -f $(BIN)
