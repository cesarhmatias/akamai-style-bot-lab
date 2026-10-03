# syntax=docker/dockerfile:1
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go vet ./... && go test ./... \
 && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /edge .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /edge /edge
EXPOSE 8443
ENV LISTEN=:8443 UPSTREAM=http://api:8000
ENTRYPOINT ["/edge"]
