SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c
.ONESHELL:
.DELETE_ON_ERROR:
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules
MAKEFLAGS += --no-builtin-variables
.DEFAULT_GOAL := help

CARGO ?= cargo
V ?= 0
ifeq ($(V),1)
  Q :=
else
  Q := @
endif

##@ Development

.PHONY: help
help: ## Show available targets
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} \
		/^[a-zA-Z0-9_-]+:.*?##/ { printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2 } \
		/^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)

.PHONY: fmt
fmt: ## Check Rust formatting
	$(Q)$(CARGO) fmt --all --check

.PHONY: fmt-fix
fmt-fix: ## Apply Rust formatting
	$(Q)$(CARGO) fmt --all

.PHONY: lint
lint: ## Run clippy with warnings denied
	$(Q)$(CARGO) clippy --workspace --all-targets -- -D warnings

.PHONY: test
test: ## Run all unit and integration tests
	$(Q)$(CARGO) test --workspace

.PHONY: check
check: ## Run fmt, lint, and tests
	$(Q)$(MAKE) fmt
	$(Q)$(MAKE) lint
	$(Q)$(MAKE) test

.PHONY: e2e
e2e: ## Run end-to-end tests
	$(Q)$(CARGO) test --test e2e -- --nocapture

.PHONY: docs
docs: ## Build workspace documentation
	$(Q)$(CARGO) doc --workspace --no-deps

.PHONY: dev-server
dev-server: ## Run sshkmad using config/dev.toml
	$(Q)$(CARGO) run --bin sshkmad -- serve --config config/dev.toml

.PHONY: clean
clean: ## Remove build artifacts
	$(Q)$(CARGO) clean

##@ Release

.PHONY: build
build: ## Build release binaries
	$(Q)$(CARGO) build --release

.PHONY: install
install: build ## Install release binaries to PREFIX
	$(Q)install -D target/release/sshkma $(DESTDIR)$(PREFIX)/bin/sshkma
	$(Q)install -D target/release/sshkmad $(DESTDIR)$(PREFIX)/bin/sshkmad

PREFIX ?= /usr/local
DESTDIR ?=
