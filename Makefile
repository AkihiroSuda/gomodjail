# Files are installed under $(DESTDIR)/$(PREFIX)
PREFIX ?= /usr/local
DEST := $(shell echo "$(DESTDIR)/$(PREFIX)" | sed 's:///*:/:g; s://*$$::')

VERSION ?=$(shell git describe --match 'v[0-9]*' --dirty='.m' --always --tags)
VERSION_SYMBOL := github.com/AkihiroSuda/gomodjail/cmd/gomodjail/version.Version

export SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct)

GO ?= go
GO_LDFLAGS ?= -s -w -X $(VERSION_SYMBOL)=$(VERSION)
GO_BUILD ?= $(GO) build -trimpath -ldflags="$(GO_LDFLAGS)"

STATIC ?=
ifeq ($(STATIC),1)
	GO_LDFLAGS += -extldflags -static
	export CGO_ENABLED=1
endif

DOCKER ?= docker
DOCKER_BUILD ?= $(DOCKER) build --build-arg SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH)

.PHONY: all
all: binaries

.PHONY: binaries
binaries: _output/bin/gomodjail
	ln -sf _output/bin/gomodjail gomodjail

.PHONY: _output/bin/gomodjail
_output/bin/gomodjail:
	$(GO_BUILD) -o $@ ./cmd/gomodjail

.PHONY: install
install: uninstall
	mkdir -p "$(DEST)"
	install _output/bin/gomodjail "$(DEST)/bin/gomodjail"

.PHONY: uninstall
uninstall:
	rm -rf "$(DEST)/bin/gomodjail"

.PHONY: clean
clean:
	rm -rf _output _artifacts

define make_artifact
	$(DOCKER_BUILD) --platform $(1)/$(2) --output type=tar,dest=_artifacts/gomodjail-$(VERSION).$(1)-$(2).tar.gz .
endef

.PHONY: artifacts
artifacts:
	rm -rf _artifacts
	mkdir -p _artifacts
	$(call make_artifact,linux,amd64)
	$(call make_artifact,linux,arm64)
	(cd _artifacts ; sha256sum *) > SHA256SUMS
	mv SHA256SUMS _artifacts/SHA256SUMS
	touch -d @$(SOURCE_DATE_EPOCH) _artifacts/*
