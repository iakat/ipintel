FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags="-s -w" -o /ip-intel ./cmd/ip-intel

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /ip-intel /ip-intel
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/ip-intel"]
CMD ["serve", "--db", "/data/ipintel.bin", "--addr", ":8080"]
