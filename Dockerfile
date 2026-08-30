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
FROM golang:1.23-alpine AS build
ENV GOTOOLCHAIN=local
WORKDIR /src
RUN apk add --no-cache git
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=0.1.0
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /out/api       ./cmd/api      && \
    CGO_ENABLED=0 go build -ldflags "-s -w" -o /out/gateway   ./cmd/gateway  && \
    CGO_ENABLED=0 go build -ldflags "-s -w" -o /out/scheduler ./cmd/scheduler && \
    CGO_ENABLED=0 go build -ldflags "-s -w" -o /out/migrate   ./cmd/migrate && \
    CGO_ENABLED=0 go build -ldflags "-s -w" -o /out/provisioner ./cmd/provisioner

# --- runtime ---
FROM alpine:3.20
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 asm
WORKDIR /app
COPY --from=build /out/ /usr/local/bin/
# the api looks for ./web/dist relative to its working directory
COPY --from=web /web/dist /app/web/dist
USER asm
ENTRYPOINT ["/usr/local/bin/api"]
