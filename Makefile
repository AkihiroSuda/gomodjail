# Files are installed under $(DESTDIR)/$(PREFIX)
PREFIX ?= /usr/local
DEST := $(shell echo "$(DESTDIR)/$(PREFIX)" | sed 's:///*:/:g; s://*$$::')

VERSION ?=$(shell git describe --match 'v[0-9]*' --dirty='.m' --always --tags)
VERSION_SYMBOL := github.com/AkihiroSuda/gomodjail/cmd/gomodjail/version.Version

export SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct)
SOURCE_DATE_EPOCH_TOUCH := $(shell date -r $(SOURCE_DATE_EPOCH) +%Y%m%d%H%M.%S)

GO ?= go
GO_LDFLAGS ?= -s -w -X $(VERSION_SYMBOL)=$(VERSION)
GO_BUILD ?= $(GO) build -trimpath -ldflags="$(GO_LDFLAGS)"
GOOS ?= $(shell $(GO) env GOOS)
GOARCH ?= $(shell $(GO) env GOARCH)

STATIC ?=
ifeq ($(STATIC),1)
	GO_LDFLAGS += -extldflags -static
	export CGO_ENABLED=0
endif

BINARIES := _output/bin/gomodjail
ifeq ($(GOOS),darwin)
	BINARIES += _output/lib/libgomodjail_hook_darwin.dylib
ifneq (,$(findstring arm64,$(GOARCH)))
	CFLAGS += -arch arm64e
else ifneq (,$(findstring amd64,$(GOARCH)))
	CFLAGS += -arch x86_64
endif
endif

TAR ?= tar

.PHONY: all
all: binaries

.PHONY: binaries
binaries: $(BINARIES)

.PHONY: _output/bin/gomodjail
_output/bin/gomodjail:
	$(GO_BUILD) -o $@ ./cmd/gomodjail

%.o: %.c *.h
	$(CC) $(CFLAGS) -c $< -o $@

_output/lib/libgomodjail_hook_darwin.dylib: $(patsubst %.c, %.o, $(wildcard libgomodjail_hook_darwin/*.c))
	mkdir -p _output/lib
	$(CC) $(CFLAGS) -o $@ $(LDFLAGS) -ldl -dynamiclib $^

.PHONY: install
install: uninstall
	mkdir -p "$(DEST)/bin"
	cp -a _output/bin/gomodjail "$(DEST)/bin/gomodjail"
ifeq ($(GOOS),darwin)
	mkdir -p "$(DEST)/lib"
	cp -a _output/lib/libgomodjail_hook_darwin.dylib "$(DEST)/lib/libgomodjail_hook_darwin.dylib"
endif

.PHONY: uninstall
uninstall:
	rm -f "$(DEST)/bin/gomodjail"
ifeq ($(GOOS),darwin)
	rm -f "$(DEST)/lib/libgomodjail_hook_darwin.dylib"
endif

# clean does not remove _artifacts
.PHONY: clean
clean:
	rm -rf _output libgomodjail_hook_darwin/*.o

define touch_recursive
	find "$(1)" -exec touch -t $(SOURCE_DATE_EPOCH_TOUCH) {} +
endef

define make_artifact
	make clean
	GOOS=$(1) GOARCH=$(2) make
	$(call touch_recursive,_output)
	$(TAR) -C _output/ --no-xattrs --numeric-owner --uid 0 --gid 0 --option !timestamp -czvf _artifacts/gomodjail-$(VERSION).$(1)-$(2).tar.gz ./
endef

# Needs to be executed on macOS
.PHONY: artifacts
artifacts:
	rm -rf _artifacts
	mkdir -p _artifacts
	$(call make_artifact,linux,amd64)
	$(call make_artifact,linux,arm64)
	$(call make_artifact,darwin,amd64)
	$(call make_artifact,darwin,arm64)
	make clean
	go version | tee _artifacts/build-env.txt
	echo --- >> _artifacts/build-env.txt
	sw_vers | tee -a _artifacts/build-env.txt
	echo --- >> _artifacts/build-env.txt
	pkgutil --pkg-info=com.apple.pkg.CLTools_Executables | tee -a _artifacts/build-env.txt
	echo --- >> _artifacts/build-env.txt
	$(CC) --version | tee -a _artifacts/build-env.txt
	(cd _artifacts ; sha256sum *) > SHA256SUMS
	mv SHA256SUMS _artifacts/SHA256SUMS
	$(call touch_recursive,_artifacts)
