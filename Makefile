# Copyright (c) Abstract Machines
# SPDX-License-Identifier: Apache-2.0

AM_DOCKER_IMAGE_NAME_PREFIX ?= ghcr.io/absmach
BUILD_DIR = build
DOCKER = $(addprefix docker_,certs)
DOCKER_DEV = $(addprefix docker_dev_,certs)
CGO_ENABLED ?= 0
GOARCH ?= amd64
VERSION ?= $(shell git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0")
COMMIT ?= $(shell git rev-parse HEAD)
TIME ?= $(shell date +%F_%T)
USER_REPO ?= $(shell git remote get-url origin | sed -e 's/.*\/\([^/]*\)\/\([^/]*\).*/\1_\2/' )
empty:=
space:= $(empty) $(empty)
# Docker compose project name should follow this guidelines: https://docs.docker.com/compose/reference/#use--p-to-specify-a-project-name
DOCKER_PROJECT ?= $(shell echo $(subst $(space),,$(USER_REPO)) | tr -c -s '[:alnum:][=-=]' '_' | tr '[:upper:]' '[:lower:]')
MOCKERY_VERSION=v2.43.2

define compile_service
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) GOARM=$(GOARM) \
	go build -ldflags "-s -w \
	-X 'github.com/absmach/certs/http.BuildTime=$(TIME)' \
	-X 'github.com/absmach/certs/internal/http.Version=$(VERSION)' \
	-X 'github.com/absmach/certs/internal/http.Commit=$(COMMIT)'" \
	-o ${BUILD_DIR}/$(1) cmd/$(1)/main.go
endef

define make_docker
	docker build \
		--no-cache \
		--build-arg SVC=certs \
		--tag=$(AM_DOCKER_IMAGE_NAME_PREFIX)/certs \
		-f docker/Dockerfile .
endef

define make_docker_dev
	docker build \
		--no-cache \
		--build-arg SVC=certs \
		--build-arg GOARCH=$(GOARCH) \
		--build-arg GOARM=$(GOARM) \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg TIME=$(TIME) \
		--tag=$(AM_DOCKER_IMAGE_NAME_PREFIX)/certs \
		-f docker/Dockerfile.dev .
endef

all: certs cli

.PHONY: all certs docker docker_dev cli mocks 

clean:
	rm -rf ${BUILD_DIR}

cleandocker:
	# Stops containers and removes containers, networks, volumes, and images created by up
	docker compose -f docker/docker-compose.yml -p $(DOCKER_PROJECT) down --rmi all -v --remove-orphans

install:
	for file in $(BUILD_DIR)/*; do \
		cp $$file $(GOBIN)/certs-`basename $$file`; \
	done

mocks:
	@which mockery > /dev/null || go install github.com/vektra/mockery/v2@$(MOCKERY_VERSION)
	mockery --config ./mockery.yaml

test: mocks
	go test -v -race -count 1 -tags test $(shell go list ./... | grep -v 'vendor\|cmd')

proto:
	protoc -I. --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative certs.proto

certs:
	$(call compile_service,certs)

cli:
	$(call compile_service,cli)

$(DOCKER):
	$(call make_docker,$(@),$(GOARCH))

$(DOCKER_DEV):
	$(call make_docker_dev,$(@))

docker: $(DOCKER)
docker_dev: $(DOCKER_DEV)

run:
	docker compose -f docker/docker-compose.yml --env-file docker/.env -p absmach up

deploy:
	docker compose -f docker/docker-compose.yml pull
	docker compose -f docker/docker-compose.yml --env-file docker/.env -p absmach up -d
