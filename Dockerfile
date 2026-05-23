FROM golang:1.25-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /bin/excalibase-auth ./cmd/server/

# distroless/static: minimal runtime, no shell, runs as nonroot, ships ca-certificates.
FROM gcr.io/distroless/static:nonroot

COPY --from=build /bin/excalibase-auth /bin/excalibase-auth

USER nonroot:nonroot
EXPOSE 24000

ENTRYPOINT ["/bin/excalibase-auth"]
