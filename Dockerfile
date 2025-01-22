FROM --platform=$BUILDPLATFORM golang:1.23.5-bookworm@sha256:3149bc5043fa58cf127fd8db1fdd4e533b6aed5a40d663d4f4ae43d20386665f AS build
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
