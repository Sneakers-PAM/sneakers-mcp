# syntax=docker/dockerfile:1
ARG GO_VERSION=1.26.6
FROM golang:${GO_VERSION} AS build
ARG VERSION=dev
ARG COMMIT=unknown
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-X main.version=${VERSION} -X main.commit=${COMMIT}" -o /out/mcp ./cmd/mcp

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/mcp /mcp
USER nonroot:nonroot
ENTRYPOINT ["/mcp"]
