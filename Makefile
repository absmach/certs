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
DOCKER_COMPOSE_COMMANDS_SUPPORTED := up down config
DEFAULT_DOCKER_COMPOSE_COMMAND  := up
GRPC_MTLS_CERT_FILES_EXISTS = 0
MOCKERY = $(GOBIN)/mockery
MOCKERY_VERSION=3.5.3

ifneq ($(filter run%,$(firstword $(MAKECMDGOALS))),)
  temp_args := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
  DOCKER_COMPOSE_COMMAND := $(if $(filter $(DOCKER_COMPOSE_COMMANDS_SUPPORTED),$(temp_args)), $(filter $(DOCKER_COMPOSE_COMMANDS_SUPPORTED),$(temp_args)), $(DEFAULT_DOCKER_COMPOSE_COMMAND))
  $(eval $(DOCKER_COMPOSE_COMMAND):;@)
endif

ifneq ("$(wildcard docker/ssl/certs/*-grpc-*)","")
GRPC_MTLS_CERT_FILES_EXISTS = 1
else
GRPC_MTLS_CERT_FILES_EXISTS = 0
endif

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
		--build-arg GOARCH=$(GOARCH) \
		--build-arg GOARM=$(GOARM) \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg TIME=$(TIME) \
		--tag=$(AM_DOCKER_IMAGE_NAME_PREFIX)/certs \
		-f docker/Dockerfile .
endef

define make_docker_dev
	docker build \
		--no-cache \
		--build-arg SVC=certs \
		--tag=$(AM_DOCKER_IMAGE_NAME_PREFIX)/certs \
		-f docker/Dockerfile.dev .
endef

fetch_supermq:
	@./scripts/supermq.sh

all: certs cli

.PHONY: all certs docker docker_dev cli mocks run run_certs_only check_certs check_mtls check_tls grpc_mtls_certs 

clean:
	rm -rf ${BUILD_DIR}

cleandocker:
	# Stops containers and removes containers, networks, volumes, and images created by up
	docker compose -f docker/docker-compose.yml -p $(DOCKER_PROJECT) down --rmi all -v --remove-orphans

install:
	for file in $(BUILD_DIR)/*; do \
		cp $$file $(GOBIN)/certs-`basename $$file`; \
	done

mocks: $(MOCKERY)
	@$(MOCKERY) --config ./mockery.yaml

$(MOCKERY):
	@mkdir -p $(GOBIN)
	@mkdir -p mockery
	@echo ">> downloading mockery $(MOCKERY_VERSION)..."
	@curl -sL https://github.com/vektra/mockery/releases/download/v$(MOCKERY_VERSION)/mockery_$(MOCKERY_VERSION)_Linux_x86_64.tar.gz | tar -xz -C mockery
	@mv mockery/mockery $(GOBIN)
	@rm -r mockery

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

run: check_certs
	docker compose -f docker/docker-compose.yml --env-file docker/.env -p $(DOCKER_PROJECT) $(DOCKER_COMPOSE_COMMAND) $(args)

run_certs_only: check_certs
	docker compose -f docker/docker-compose.yml --env-file docker/.env -p $(DOCKER_PROJECT) up

deploy:
	docker compose -f docker/docker-compose.yml pull
	docker compose -f docker/docker-compose.yml --env-file docker/.env -p absmach up -d

grpc_mtls_certs:
	$(MAKE) -C docker/ssl auth_grpc_certs things_grpc_certs

check_tls:
ifeq ($(GRPC_TLS),true)
	@unset GRPC_MTLS
	@echo "gRPC TLS is enabled"
	GRPC_MTLS=
else
	@unset GRPC_TLS
	GRPC_TLS=
endif

check_mtls:
ifeq ($(GRPC_MTLS),true)
	@unset GRPC_TLS
	@echo "gRPC MTLS is enabled"
	GRPC_TLS=
else
	@unset GRPC_MTLS
	GRPC_MTLS=
endif

check_certs: check_mtls check_tls
ifeq ($(GRPC_MTLS_CERT_FILES_EXISTS),0)
ifeq ($(filter true,$(GRPC_MTLS) $(GRPC_TLS)),true)
ifeq ($(filter $(DEFAULT_DOCKER_COMPOSE_COMMAND),$(DOCKER_COMPOSE_COMMAND)),$(DEFAULT_DOCKER_COMPOSE_COMMAND))
	$(MAKE) -C docker/ssl auth_grpc_certs things_grpc_certs
endif
endif
endif
