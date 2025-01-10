FROM --platform=$BUILDPLATFORM golang:1.23.4-bookworm@sha256:2e838582004fab0931693a3a84743ceccfbfeeafa8187e87291a1afea457ff7a AS build
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
