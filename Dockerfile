# Whisper CLI - multi-stage, CGO-free static build into a minimal distroless image.
# Built + pushed multi-arch (amd64/arm64) to ghcr.io/whisper-sec/whisper by .github/workflows/docker.yml.
# Pinned by DIGEST, not by a floating tag. This image is published to a public registry
# under our name, and `golang:1.25-alpine` is whatever the upstream tag pointed at on the
# day the runner pulled it. Bumping it is a deliberate edit of both halves of this line.
FROM --platform=$BUILDPLATFORM golang:1.25.13-alpine@sha256:1e0126852075c9c60731c8ba49088448b91f63e2aed97ca9d1a9791622a05946 AS build
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

# The runtime base is deliberately NOT digest-pinned, unlike the build stage above. This is
# a static binary in a distroless image, so the base contributes CA certs and little else, and
# floating the tag means those track upstream CVE fixes instead of freezing on the day we
# pinned. Say it here rather than let the pinned line above imply it applies to both.
FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.source="https://github.com/whisper-sec/whisper-cli" \
      org.opencontainers.image.description="Whisper CLI - routable agent IPv6 identity + safe egress" \
      org.opencontainers.image.licenses="MIT" \
      io.modelcontextprotocol.server.name="io.github.whisper-sec/whisper"
COPY --from=build /out/whisper /usr/local/bin/whisper
ENTRYPOINT ["whisper"]
