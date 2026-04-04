FROM golang:1.24-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /bin/excalibase-auth ./cmd/server/

FROM alpine:3.20

RUN apk add --no-cache ca-certificates
COPY --from=build /bin/excalibase-auth /bin/excalibase-auth

EXPOSE 24000

ENTRYPOINT ["/bin/excalibase-auth"]
