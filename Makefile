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
