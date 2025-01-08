// Example profile for `docker` (Docker CLI, not Docker daemon)
//
// From https://github.com/docker/cli/blob/v26.1.3/vendor.mod
// LICENSE: https://github.com/docker/cli/blob/v26.1.3/LICENSE (Apache License 2.0)

module github.com/docker/cli

// 'vendor.mod' enables use of 'go mod vendor' to managed 'vendor/' directory.
// There is no 'go.mod' file, as that would imply opting in for all the rules
// around SemVer, which this repo cannot abide by as it uses CalVer.

go 1.21

require (
	dario.cat/mergo v1.0.0 // gomodjail:confined
	github.com/containerd/containerd v1.7.15 // gomodjail:confined
	github.com/creack/pty v1.1.21 // gomodjail:confined
	github.com/distribution/reference v0.5.0 // gomodjail:confined
	github.com/docker/distribution v2.8.3+incompatible // gomodjail:confined
	github.com/docker/docker v26.1.3-0.20240515073302-8e96db1c328d+incompatible
	github.com/docker/docker-credential-helpers v0.8.1 // gomodjail:confined
	github.com/docker/go-connections v0.5.0
	github.com/docker/go-units v0.5.0 // gomodjail:confined
	github.com/fvbommel/sortorder v1.0.2 // gomodjail:confined
	github.com/gogo/protobuf v1.3.2 // gomodjail:confined
	github.com/google/go-cmp v0.6.0 // gomodjail:confined
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510 // gomodjail:confined
	github.com/mattn/go-runewidth v0.0.15 // gomodjail:confined
	github.com/mitchellh/mapstructure v1.5.0 // gomodjail:confined
	github.com/moby/patternmatcher v0.6.0 // gomodjail:confined
	github.com/moby/swarmkit/v2 v2.0.0-20240227173239-911c97650f2e // gomodjail:confined
	github.com/moby/sys/sequential v0.5.0 // gomodjail:confined
	github.com/moby/sys/signal v0.7.0 // gomodjail:confined
	github.com/moby/term v0.5.0
	github.com/morikuni/aec v1.0.0 // gomodjail:confined
	github.com/opencontainers/go-digest v1.0.0 // gomodjail:confined
	github.com/opencontainers/image-spec v1.1.0-rc5 // gomodjail:confined
	github.com/pkg/errors v0.9.1 // gomodjail:confined
	github.com/sirupsen/logrus v1.9.3 // gomodjail:confined
	github.com/spf13/cobra v1.8.0
	github.com/spf13/pflag v1.0.5 // gomodjail:confined
	github.com/theupdateframework/notary v0.7.1-0.20210315103452-bf96a202a09a // gomodjail:confined
	github.com/tonistiigi/go-rosetta v0.0.0-20200727161949-f79598599c5d // gomodjail:confined
	github.com/xeipuuv/gojsonschema v1.2.0 // gomodjail:confined
	go.opentelemetry.io/otel v1.21.0
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc v0.44.0 // gomodjail:confined
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.21.0 // gomodjail:confined
	go.opentelemetry.io/otel/metric v1.21.0
	go.opentelemetry.io/otel/sdk v1.21.0
	go.opentelemetry.io/otel/sdk/metric v1.21.0
	go.opentelemetry.io/otel/trace v1.21.0 // gomodjail:confined
	golang.org/x/sync v0.6.0
	golang.org/x/sys v0.18.0
	golang.org/x/term v0.18.0 // gomodjail:confined
	golang.org/x/text v0.14.0 // gomodjail:confined
	gopkg.in/yaml.v2 v2.4.0 // gomodjail:confined
	gotest.tools/v3 v3.5.1 // gomodjail:confined
	tags.cncf.io/container-device-interface v0.6.2 // gomodjail:confined
)

require (
	github.com/Azure/go-ansiterm v0.0.0-20210617225240-d185dfc1b5a1 // indirect // gomodjail:confined
	github.com/Microsoft/go-winio v0.6.1 // indirect // gomodjail:confined
	github.com/Microsoft/hcsshim v0.11.4 // indirect // gomodjail:confined
	github.com/beorn7/perks v1.0.1 // indirect // gomodjail:confined
	github.com/cenkalti/backoff/v4 v4.2.1 // indirect // gomodjail:confined
	github.com/cespare/xxhash/v2 v2.2.0 // indirect // gomodjail:confined
	github.com/containerd/log v0.1.0 // indirect // gomodjail:confined
	github.com/docker/go v1.5.1-1.0.20160303222718-d30aec9fd63c
	github.com/docker/go-events v0.0.0-20190806004212-e31b211e4f1c // indirect // gomodjail:confined
	github.com/docker/go-metrics v0.0.1 // indirect // gomodjail:confined
	github.com/felixge/httpsnoop v1.0.4 // indirect // gomodjail:confined
	github.com/go-logr/logr v1.4.1 // indirect // gomodjail:confined
	github.com/go-logr/stdr v1.2.2 // indirect // gomodjail:confined
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/gorilla/mux v1.8.1 // indirect // gomodjail:confined
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.16.0 // indirect // gomodjail:confined
	github.com/inconshreveable/mousetrap v1.1.0 // indirect // gomodjail:confined
	github.com/klauspost/compress v1.17.4 // indirect // gomodjail:confined
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect // gomodjail:confined
	github.com/miekg/pkcs11 v1.1.1 // indirect // gomodjail:confined
	github.com/moby/docker-image-spec v1.3.1 // indirect // gomodjail:confined
	github.com/moby/sys/symlink v0.2.0 // indirect // gomodjail:confined
	github.com/moby/sys/user v0.1.0 // indirect // gomodjail:confined
	github.com/prometheus/client_golang v1.17.0 // indirect // gomodjail:confined
	github.com/prometheus/client_model v0.5.0 // indirect // gomodjail:confined
	github.com/prometheus/common v0.44.0 // indirect // gomodjail:confined
	github.com/prometheus/procfs v0.12.0 // indirect // gomodjail:confined
	github.com/rivo/uniseg v0.2.0 // indirect // gomodjail:confined
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect // gomodjail:confined
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect // gomodjail:confined
	go.etcd.io/etcd/raft/v3 v3.5.6 // indirect // gomodjail:confined
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.46.1 // indirect // gomodjail:confined
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.21.0 // indirect // gomodjail:confined
	go.opentelemetry.io/proto/otlp v1.0.0 // indirect // gomodjail:confined
	golang.org/x/crypto v0.21.0 // indirect // gomodjail:confined
	golang.org/x/mod v0.14.0 // indirect // gomodjail:confined
	golang.org/x/net v0.23.0 // indirect // gomodjail:confined
	golang.org/x/time v0.3.0 // indirect // gomodjail:confined
	golang.org/x/tools v0.16.0 // indirect // gomodjail:confined
	google.golang.org/genproto/googleapis/api v0.0.0-20231002182017-d307bd883b97 // indirect // gomodjail:confined
	google.golang.org/genproto/googleapis/rpc v0.0.0-20231016165738-49dd2c1f3d0b // indirect // gomodjail:confined
	google.golang.org/grpc v1.60.1 // indirect
	google.golang.org/protobuf v1.33.0 // indirect
)
