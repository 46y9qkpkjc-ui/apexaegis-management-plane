# Multi-arch Dockerfile for management-plane
# Uses the buildkit provided TARGETARCH to cross-build for the current platform.

ARG TARGETARCH
FROM golang:1.26 AS builder
ARG TARGETARCH
ENV GOARCH=${TARGETARCH:-amd64}
RUN apt-get update && apt-get install -y --no-install-recommends \
    git build-essential ca-certificates && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY go.mod go.sum ./
COPY proto/ proto/
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH="$GOARCH" \
    go build -ldflags="-s -w" -o /app/management-plane ./cmd/server

FROM alpine:3.19
RUN apk add --no-cache ca-certificates bash

COPY --from=builder /app/management-plane /usr/local/bin/management-plane
COPY --from=builder /src/internal/db/migrations /migrations
COPY start.sh /usr/local/bin/start.sh
RUN chmod +x /usr/local/bin/management-plane /usr/local/bin/start.sh

ENV MIGRATIONS_DIR=/migrations
ENV LISTEN_ADDR=:443

EXPOSE 443
ENTRYPOINT ["/usr/local/bin/start.sh"]
