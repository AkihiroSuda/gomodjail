FROM --platform=$BUILDPLATFORM golang:1.23.6-bookworm@sha256:441f59f8a2104b99320e1f5aaf59a81baabbc36c81f4e792d5715ef09dd29355 AS build
ARG TARGETARCH
RUN --mount=type=cache,target=/root/.cache \
  --mount=type=cache,target=/go \
  --mount=type=bind,src=.,target=/src,rw=true \
  cd /src && \
  GOARCH=$TARGETARCH STATIC=1 make && \
  readelf -d _output/bin/gomodjail | grep -q "no dynamic" && \
  cp -a _output /

FROM scratch
COPY --from=build /_output /
