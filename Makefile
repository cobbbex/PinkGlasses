GO ?= go
BIN := bin

.PHONY: all build tidy vet test clean migrate api gateway scheduler worker

all: build

tidy:
	$(GO) mod tidy

build: tidy
	$(GO) build -o $(BIN)/api      ./cmd/api
	$(GO) build -o $(BIN)/gateway  ./cmd/gateway
	$(GO) build -o $(BIN)/scheduler ./cmd/scheduler
	$(GO) build -o $(BIN)/worker   ./cmd/worker
	$(GO) build -o $(BIN)/migrate  ./cmd/migrate

vet:
	$(GO) vet ./...

test:
	$(GO) test ./...

migrate: build
	$(BIN)/migrate up

clean:
	rm -rf $(BIN)

# Run one pipeline stage in isolation and print the observations it produced.
# Backs the Phase 13 gates:
#   make tool-test STAGE=passive_enum TARGET=example.com
#   make tool-test STAGE=port_scan    TARGET=scanme.nmap.org PROFILE=standard
#
# Runs inside the worker container so the real toolchain is present.
STAGE   ?= dns_resolve
TARGET  ?= example.com
PROFILE ?= standard
TIMEOUT ?= 5m

.PHONY: tool-test tool-test-local
tool-test:
	docker compose exec -e ASM_TEST_PROFILE=$(PROFILE) worker \
		/usr/local/bin/worker -stage $(STAGE) -target $(TARGET) -timeout $(TIMEOUT)

# Same, but with the binary built on this host (Go fallbacks only).
tool-test-local: build
	ASM_TEST_PROFILE=$(PROFILE) $(BIN)/worker -stage $(STAGE) -target $(TARGET) -timeout $(TIMEOUT)
