# Multi-arch Dockerfile for management-plane
# Uses the buildkit provided TARGETARCH to cross-build for the current platform.

ARG TARGETARCH
FROM golang:1.26 AS builder
ARG TARGETARCH
ENV GOARCH=${TARGETARCH:-amd64}
# Install git and build tools on Debian-based image
RUN apt-get update && apt-get install -y --no-install-recommends \
    git build-essential ca-certificates && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Static, lean build
RUN CGO_ENABLED=0 GOOS=linux GOARCH="$GOARCH" \
    go build -ldflags="-s -w" -o /app/management-plane ./cmd/server

FROM alpine:3.19
RUN apk add --no-cache ca-certificates bash
COPY --from=builder /app/management-plane /usr/local/bin/management-plane
COPY migrate-db.sh /usr/local/bin/migrate-db.sh
COPY ./cmd/dbmigrate /usr/local/bin/dbmigrate-src
COPY start.sh /usr/local/bin/start.sh
RUN chmod +x /usr/local/bin/management-plane /usr/local/bin/migrate-db.sh /usr/local/bin/start.sh
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/start.sh"]
