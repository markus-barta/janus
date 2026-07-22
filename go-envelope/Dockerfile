FROM golang:1.26.5-alpine3.24@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build
ARG JANUS_BUILD_COMMIT=unknown
ARG JANUS_BUILD_TIME=unknown
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X 'main.buildCommit=${JANUS_BUILD_COMMIT}' -X 'main.buildTime=${JANUS_BUILD_TIME}'" -o /out/janus .

FROM alpine:3.22.5@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce
LABEL org.opencontainers.image.title="Janus governance envelope"
LABEL org.opencontainers.image.source="https://github.com/markus-barta/janus"
LABEL org.opencontainers.image.licenses="AGPL-3.0-only"
LABEL org.opencontainers.image.base.name="docker.io/library/alpine:3.22.5"
LABEL org.opencontainers.image.base.digest="sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce"
RUN addgroup -S janus && adduser -S -G janus janus
WORKDIR /app
COPY --from=build /out/janus /app/janus
RUN mkdir -p /data && chown janus:janus /data
USER janus
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD wget -qO- http://127.0.0.1:8080/readyz | grep -q '"ready":true' || exit 1
ENTRYPOINT ["/app/janus"]
