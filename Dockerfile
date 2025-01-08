FROM tonistiigi/xx:1.6.1@sha256:923441d7c25f1e2eb5789f82d987693c47b8ed987c4ab3b075d6ed2b5d6779a3 AS xx

FROM --platform=$BUILDPLATFORM golang:1.23.4-bookworm@sha256:2e838582004fab0931693a3a84743ceccfbfeeafa8187e87291a1afea457ff7a AS build
COPY --from=xx / /
ENV DEBIAN_FRONTEND=noninteractive
ARG TARGETARCH
RUN xx-apt-get update -qq && xx-apt-get install -qq --no-install-recommends \
    binutils \
    gcc \
    libc6-dev \
    libseccomp-dev \
    pkg-config
RUN --mount=type=cache,target=/root/.cache \
  --mount=type=cache,target=/go \
  --mount=type=bind,src=.,target=/src,rw=true \
  cd /src && \
  GO=xx-go STATIC=1 make && \
  xx-verify --static _output/bin/gomodjail && \
  cp -a _output /

FROM scratch
COPY --from=build /_output /
