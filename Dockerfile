# Whisper CLI — multi-stage, CGO-free static build into a minimal distroless image.
# Built + pushed multi-arch (amd64/arm64) to ghcr.io/whisper-sec/whisper by .github/workflows/docker.yml.
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
        -trimpath -ldflags "-s -w -X github.com/whisper-sec/whisper-cli/internal/cli.Version=${VERSION}" \
        -o /out/whisper ./cmd/whisper

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.source="https://github.com/whisper-sec/whisper-cli" \
      org.opencontainers.image.description="Whisper CLI — routable agent IPv6 identity + safe egress" \
      org.opencontainers.image.licenses="MIT" \
      io.modelcontextprotocol.server.name="io.github.whisper-sec/whisper"
COPY --from=build /out/whisper /usr/local/bin/whisper
ENTRYPOINT ["whisper"]
