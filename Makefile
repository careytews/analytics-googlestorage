
VERSION=$(shell git describe | sed 's/^v//')

all godeps godepstree build container push clean: bin/dep
	(TOPDIR=$$(pwd); cd src/analytics; make $@ TOPDIR=$${TOPDIR} VERSION=${VERSION})

version:
	@echo ${VERSION}

bin/dep:
	

BRANCH=master
PREFIX=resources/$(shell basename $(shell git remote get-url origin))
FILE=${PREFIX}/ksonnet/version.jsonnet
REPO=$(shell git remote get-url origin)

tools: phony
	if [ ! -d tools ]; then \
		git clone git@github.com:trustnetworks/cd-tools tools; \
	fi; \
	(cd tools; git pull)

phony:

bump-version: tools
	tools/bump-version

update-cluster-config: tools
	tools/update-cluster-config ${BRANCH} ${PREFIX} ${FILE} ${VERSION} \
	    ${REPO}
