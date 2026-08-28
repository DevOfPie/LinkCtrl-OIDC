# The whole build, and every gate CI runs.
#
# There is no phase loop in this repository and no milestone file: the owner set
# its process as *the same gates, no phase loop* — CI green, sabotage-verified
# tests, a changelog, a checksummed release. `make check` is those gates as far
# as a machine can run them; the sabotage half is a person's, and scripts/sabotage.sh
# is what makes it repeatable.

MODULE  := oidc.wasm
VERSION := $(shell sed -n 's/^const Version = "\(.*\)"$$/\1/p' oidc/version.go)
DIST    := dist
BUNDLE  := $(DIST)/linkctrl-oidc-$(VERSION).tar.gz

# -buildvcs=false is not tidiness. Go stamps the VCS revision and a `vcs.modified`
# flag into a main package built inside a checkout, so the same source produces
# different bytes depending on which commit is checked out and whether the tree
# is clean — and produces different bytes again from a `git archive` tarball,
# which has no VCS at all. That is the opposite of what a published digest is
# for. Provenance is the release workflow's attestation, which says which
# workflow on which commit produced the artifact and does not have to be inside
# the bytes to do it.
GOFLAGS_WASM := -trimpath -buildvcs=false -buildmode=c-shared

.PHONY: all check build manifest bundle test vet fmt clean version

all: check

## check — everything CI runs, in the order a failure is cheapest to read in.
check: fmt vet test build

## fmt — gofmt is a gate rather than a suggestion; an unformatted file fails.
fmt:
	@out=$$(gofmt -l . ); \
	if [ -n "$$out" ]; then echo "gofmt would change:"; echo "$$out"; exit 1; fi

vet:
	go vet ./...
	GOOS=wasip1 GOARCH=wasm go vet ./...

## test — the unit tests, and the SQL ones when a server is named.
##
## OIDC_TEST_PSQL_DSN puts every statement this add-on issues through a real
## Postgres. Unset, those tests skip and say so.
test:
	go test ./... $(TESTFLAGS)

## build — the module and the manifest that names its digest.
##
## A reactor, which is what -buildmode=c-shared produces: package initialization
## runs when the host instantiates the module and it then stays alive to be
## called into. -trimpath so that two builds of the same commit produce the same
## bytes, which is what makes a published digest checkable by somebody else.
build: $(MODULE) manifest

$(MODULE): $(shell find . -name '*.go' -not -name '*_test.go') go.mod go.sum
	GOOS=wasip1 GOARCH=wasm go build $(GOFLAGS_WASM) -o $(MODULE) .

## manifest — addon.json, with @SHA256@ replaced by the module's real digest.
##
## The digest is the load-time half of build verification: the host checks it
## before it writes anything, so a mismatch is a refusal rather than a module
## that runs.
manifest: $(MODULE)
	@sha=$$(sha256sum $(MODULE) | cut -d' ' -f1); \
	sed "s/@SHA256@/$$sha/" addon.json.in > addon.json; \
	echo "addon.json names $(MODULE) sha256=$$sha"

## bundle — the two files as one object, with a digest over the whole thing.
##
## An operator can upload the pair or point their instance at a URL. The URL
## names a bundle: a tar, a gzipped tar or a zip holding addon.json and the
## module it names, and nothing else — no directory entry, no symlink, no path.
## The digest beside it is what makes a URL install safe, and it has to be
## published somewhere other than the page the URL is on.
bundle: build
	@mkdir -p $(DIST)
	# --mode is not optional and its absence was invisible until a release existed
	# to compare against: without it tar records each file's mode as it is on
	# disk, so the builder's umask reaches the archive and the bundle's digest
	# differs between a machine at 022 and one at 002 while every byte inside is
	# identical. The digest an operator types beside a URL has to be the same
	# number wherever it was produced, or "rebuild it and compare" proves nothing.
	tar --sort=name --owner=0 --group=0 --numeric-owner \
	    --mtime='@0' --mode='u=rw,go=r' --format=ustar \
	    -czf $(BUNDLE) addon.json $(MODULE)
	@cd $(DIST) && sha256sum $$(basename $(BUNDLE)) > SHA256SUMS
	@cat $(DIST)/SHA256SUMS

version:
	@echo $(VERSION)

clean:
	rm -f $(MODULE) addon.json
	rm -rf $(DIST)
