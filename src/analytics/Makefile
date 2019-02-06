
VERSION=unknown

TOPDIR=$(shell git rev-parse --show-toplevel)

GOFILES=googlestorage

all: godeps build container

build: ${GOFILES}

${GOFILES}: %: %.go
	GOPATH=${TOPDIR} go build $<

godeps:
	GOPATH=${TOPDIR} dep ensure -update || GOPATH=${TOPDIR} dep ensure

godepstree: godeps
	GOPATH=${TOPDIR} dep status -dot | dot -T png > ${TOPDIR}/deptree.png

container:
	docker build -t \
		gcr.io/trust-networks/analytics-googlestorage:${VERSION} \
	 	-f Dockerfile.googlestorage .

.PHONY: push
push:
	gcloud docker -- push \
	  gcr.io/trust-networks/analytics-googlestorage:${VERSION}

clean:
	git clean -Xff && rm -rf vendor/ Gopkg.lock
