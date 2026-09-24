# Control-plane image: builds the SPA and the api/gateway/scheduler/migrate
# binaries. The api serves web/dist, so the built frontend is baked in.

# --- frontend build ---
FROM node:20-alpine AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build   # emits /web/dist

# --- Go build ---
# The shipped wordlists, fetched once at build time and carried in the image so a
# deployment has them without reaching the internet. Cached until the manifest
# or the fetch tool changes.
FROM golang:1.25-alpine AS wordlists
ENV GOTOOLCHAIN=local
WORKDIR /src
COPY go.mod go.sum ./
COPY internal/wordlists/builtin ./internal/wordlists/builtin
COPY tools/fetchwordlists ./tools/fetchwordlists
RUN go run ./tools/fetchwordlists /out/wordlists

FROM golang:1.25-alpine AS build
ENV GOTOOLCHAIN=local
WORKDIR /src
RUN apk add --no-cache git
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=
ENV LDFLAGS="-s -w -X github.com/benlik386/pinkglasses/internal/version.Version=${VERSION} -X github.com/benlik386/pinkglasses/internal/version.Commit=${COMMIT}"
RUN CGO_ENABLED=0 go build -ldflags "$LDFLAGS" -o /out/api       ./cmd/api      && \
    CGO_ENABLED=0 go build -ldflags "$LDFLAGS" -o /out/gateway   ./cmd/gateway  && \
    CGO_ENABLED=0 go build -ldflags "$LDFLAGS" -o /out/scheduler ./cmd/scheduler && \
    CGO_ENABLED=0 go build -ldflags "$LDFLAGS" -o /out/migrate   ./cmd/migrate && \
    CGO_ENABLED=0 go build -ldflags "$LDFLAGS" -o /out/provisioner ./cmd/provisioner && \
    CGO_ENABLED=0 go build -ldflags "$LDFLAGS" -o /out/mcp       ./cmd/mcp

# --- runtime ---
FROM alpine:3.20
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 asm
WORKDIR /app
COPY --from=build /out/ /usr/local/bin/
COPY --from=wordlists /out/wordlists /usr/share/pinkglasses/wordlists
# the api looks for ./web/dist relative to its working directory
COPY --from=web /web/dist /app/web/dist
USER asm
ENTRYPOINT ["/usr/local/bin/api"]
