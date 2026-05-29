FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/janus .

FROM alpine:3.22
RUN addgroup -S janus && adduser -S -G janus janus
WORKDIR /app
COPY --from=build /out/janus /app/janus
RUN mkdir -p /data && chown janus:janus /data
USER janus
EXPOSE 8080
ENTRYPOINT ["/app/janus"]
