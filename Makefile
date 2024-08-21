# Copyright (c) Abstract Machines
# SPDX-License-Identifier: Apache-2.0

AM_DOCKER_IMAGE_NAME_PREFIX ?= absmach
BUILD_DIR = build
SERVICES = certs
DOCKERS = $(addprefix docker_,$(SERVICES))
DOCKERS_DEV = $(addprefix docker_dev_,$(SERVICES))
CGO_ENABLED ?= 0
GOARCH ?= amd64
VERSION ?= $(shell git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0")
COMMIT ?= $(shell git rev-parse HEAD)
TIME ?= $(shell date +%F_%T)
MOCKERY_VERSION=v2.43.2

define compile_service
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) GOARM=$(GOARM) \
	go build -ldflags "-s -w \
	-X 'github.com/absmach/certs/http.BuildTime=$(TIME)' \
	-X 'github.com/absmach/certs/internal/http.Version=$(VERSION)' \
	-X 'github.com/absmach/certs/internal/http.Commit=$(COMMIT)'" \
	-o ${BUILD_DIR}/$(1) cmd/main.go
endef

define make_docker
	$(eval svc=$(subst docker_,,$(1)))

	docker build \
		--no-cache \
		--build-arg SVC=$(svc) \
		--build-arg GOARCH=$(GOARCH) \
		--build-arg GOARM=$(GOARM) \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg TIME=$(TIME) \
		--tag=$(AM_DOCKER_IMAGE_NAME_PREFIX)/$(svc) \
		-f docker/Dockerfile .
endef

define make_docker_dev
	$(eval svc=$(subst docker_dev_,,$(1)))

	docker build \
		--no-cache \
		--build-arg SVC=$(svc) \
		--tag=$(AM_DOCKER_IMAGE_NAME_PREFIX)/$(svc) \
		-f docker/Dockerfile.dev .
endef

all: $(SERVICES)

.PHONY: all $(SERVICES) dockers dockers_dev latest release

clean:
	rm -rf ${BUILD_DIR}

cleandocker:
	# Stops containers and removes containers, networks, volumes, and images created by up
	docker-compose -f docker/docker-compose.yml down --rmi all -v --remove-orphans

ifdef pv
	# Remove unused volumes
	docker volume ls -f name=$(MF_DOCKER_IMAGE_NAME_PREFIX) -f dangling=true -q | xargs -r docker volume rm
endif

install:
	cp ${BUILD_DIR}/* $(GOBIN)

mocks:
	@which mockery > /dev/null || go install github.com/vektra/mockery/v2@$(MOCKERY_VERSION)
	mockery --config ./mockery.yaml

test: mocks
	go test -v -race -count 1 -tags test $(shell go list ./... | grep -v 'vendor\|cmd')

proto:
	protoc -I. --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative certs.proto

$(SERVICES):
	$(call compile_service,$(@))

$(DOCKERS):
	$(call make_docker,$(@),$(GOARCH))

$(DOCKERS_DEV):
	$(call make_docker_dev,$(@))

dockers: $(DOCKERS)
dockers_dev: $(DOCKERS_DEV)

run:
	docker compose -f docker/docker-compose.yml --env-file docker/.env -p absmach up

deploy:
	docker compose -f docker/docker-compose.yml pull
	docker compose -f docker/docker-compose.yml --env-file docker/.env -p absmach up -d
