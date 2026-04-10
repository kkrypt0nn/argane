FROM golang:1.26.2-bookworm AS builder

WORKDIR /app

ARG TARGETOS
ARG TARGETARCH
ARG GIT_COMMIT
ARG VERSION

ENV CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN make build VERSION=${VERSION} GIT_COMMIT=${GIT_COMMIT}

FROM gcr.io/distroless/static-debian13

COPY --from=builder /app/dist/argane /argane

USER nonroot:nonroot

ENTRYPOINT ["/argane"]
