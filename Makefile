GO ?= go
BIN := bin

.PHONY: all build tidy vet test clean migrate api gateway scheduler worker brand

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

# Re-render every raster in assets/brand/ from its SVG source, then refresh the
# copies the SPA serves out of web/public/. Needs librsvg (rsvg-convert) and
# ImageMagick; only run it after editing one of the SVGs.
BRAND := assets/brand
PUBLIC := web/public

.PHONY: brand
brand:
	rsvg-convert -w 1024 $(BRAND)/logo.svg -o $(BRAND)/logo-1024.png
	rsvg-convert -w  512 $(BRAND)/logo.svg -o $(BRAND)/logo-512.png
	for s in 512 256 128 64 32 16; do \
		rsvg-convert -w $$s -h $$s $(BRAND)/icon.svg -o $(BRAND)/icon-$$s.png; \
	done
	magick $(BRAND)/icon-256.png -define icon:auto-resize=64,48,32,16 $(BRAND)/favicon.ico
	rsvg-convert -w 1880 $(BRAND)/lockup-dark.svg  -o $(BRAND)/lockup-dark-1880.png
	rsvg-convert -w 1880 $(BRAND)/lockup-light.svg -o $(BRAND)/lockup-light-1880.png
	rsvg-convert -w 1200 -h 630 $(BRAND)/og.svg -o $(BRAND)/og.png
	cp $(BRAND)/logo.svg $(BRAND)/icon.svg $(BRAND)/favicon.ico $(BRAND)/og.png $(PUBLIC)/
	rsvg-convert -w 180 -h 180 $(BRAND)/icon.svg -o $(PUBLIC)/apple-touch-icon.png
	rsvg-convert -w 192 -h 192 $(BRAND)/icon.svg -o $(PUBLIC)/icon-192.png
	rsvg-convert -w 512 -h 512 $(BRAND)/icon.svg -o $(PUBLIC)/icon-512.png
