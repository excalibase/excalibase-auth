SHELL := /bin/bash
GO ?= go
DOCKER_DIR := devbox/docker

BLUE := \033[1;34m
GREEN := \033[1;32m
RED := \033[1;31m
RESET := \033[0m

.PHONY: help
help:
	@echo "$(BLUE)excalibase-auth$(RESET)"
	@echo ""
	@echo "$(GREEN)Build:$(RESET)"
	@echo "  make build              - Build auth server binary"
	@echo ""
	@echo "$(GREEN)Test:$(RESET)"
	@echo "  make test               - Run unit + integration tests"
	@echo "  make test.unit          - Run unit tests only (no docker)"
	@echo "  make test.e2e           - Run E2E tests (requires docker)"
	@echo ""
	@echo "$(GREEN)Docker:$(RESET)"
	@echo "  make docker.build       - Build auth Docker image"
	@echo "  make docker.up          - Start auth + PostgreSQL"
	@echo "  make docker.down        - Stop all services"
	@echo ""
	@echo "$(GREEN)Dev:$(RESET)"
	@echo "  make dev                - Start auth server (dev mode)"

.PHONY: build
build:
	@echo "$(BLUE)Building auth server...$(RESET)"
	@$(GO) build -o bin/excalibase-auth ./cmd/server/

.PHONY: test
test:
	@echo "$(BLUE)Running unit + integration tests...$(RESET)"
	@$(GO) test ./... -count=1 -timeout=120s

.PHONY: test.unit
test.unit:
	@echo "$(BLUE)Running unit tests...$(RESET)"
	@$(GO) test ./... -short -count=1

.PHONY: test.e2e
test.e2e: docker.up
	@echo "$(BLUE)Waiting for PostgreSQL...$(RESET)"
	@sleep 3
	@echo "$(BLUE)Running E2E tests...$(RESET)"
	@$(GO) test ./e2e/ -tags=e2e -v -count=1 -timeout=60s; \
		status=$$?; \
		$(MAKE) docker.down; \
		exit $$status

.PHONY: docker.build
docker.build:
	@echo "$(BLUE)Building auth Docker image...$(RESET)"
	@docker build -t excalibase-auth .

.PHONY: docker.up
docker.up:
	@echo "$(BLUE)Starting auth + PostgreSQL...$(RESET)"
	@cd $(DOCKER_DIR) && docker compose up -d --build --wait

.PHONY: docker.down
docker.down:
	@echo "$(BLUE)Stopping all services...$(RESET)"
	@cd $(DOCKER_DIR) && docker compose down -v

.PHONY: dev
dev:
	@echo "$(BLUE)Starting auth server (dev)...$(RESET)"
	@$(GO) run ./cmd/server/
