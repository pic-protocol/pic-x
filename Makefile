# PIC-X — Makefile
#
# The same entry points as Taskfile.yml, for people who would rather type `make`. Both files drive
# the same commands; neither is generated from the other, so a change to one belongs in the other.
#
#   make            # the target list
#   make help       # the same thing, said out loud
#   make <target> VAR=value ...
#
# Task names that carry a colon cannot carry one here — Make reads `audit:verify` as a target named
# `audit` that depends on `verify`. They keep the same words with a dash:
#
#   task audit:verify        -> make audit-verify
#   task check:seams         -> make check-seams
#   task check:core-deps     -> make check-core-deps
#   task check:supply-chain  -> make check-supply-chain
#
# `task cli -- --help` has no Make equivalent either: everything after `--` belongs to Make. Use the
# named form, `make cli ARGS=--help`, which the Taskfile accepts too.

SHELL := /bin/bash

.DEFAULT_GOAL := help

# ---------------------------------------------------------------------------------------------
# Parameters. Every one of them can be set on the command line: `make test PKG=pic-x-core`.
# ---------------------------------------------------------------------------------------------

PKG               ?=
RELEASE           ?=
ARGS              ?=
FILTER            ?=
NOCAPTURE         ?=
FEATURES          ?= --all-features
BENCH             ?=

CONFIG            ?=
LOG_LEVEL         ?=
LOG_FORMAT        ?=
PUBLIC_HTTP_ADDR  ?=
TELEMETRY_ADDR    ?=
ADMIN_ADDR        ?=

TAG               ?= pic-x:local
VOLUME            ?=
KEYS              ?=

PYTHON            ?= python3

KEYCLOAK_URL           ?= http://localhost:18080
KEYCLOAK_REALM         ?= acme-idp
KEYCLOAK_CLIENT_ID     ?= acme-idp-client
KEYCLOAK_CLIENT_SECRET ?= acme-idp-client-secret
KEYCLOAK_USERNAME      ?= alice
KEYCLOAK_PASSWORD      ?= alice-password

# `--workspace` unless a single crate was named, which is what every cargo target here wants.
scope    = $(if $(PKG),-p $(PKG),--workspace)
profile  = $(if $(RELEASE),--release)

# A --volume argument needs an absolute host path. A VOLUME given as one is used as it stands;
# a relative one is taken from the repository, which is where the defaults live.
host_path = $(if $(filter /%,$(1)),$(1),$$(pwd)/$(1))

# The serve invocation, shared by run, run-as-local-tls and run-as-prod. $(1) is the config file;
# each flag appears only when its parameter was given, so an unset one leaves CONFIG to decide.
serve_cmd = cargo run $(profile) --bin pic-x -- $(1) \
	$(if $(LOG_LEVEL),--log-level $(LOG_LEVEL)) \
	$(if $(LOG_FORMAT),--log-format $(LOG_FORMAT)) \
	$(if $(PUBLIC_HTTP_ADDR),--public-http-addr $(PUBLIC_HTTP_ADDR)) \
	$(if $(TELEMETRY_ADDR),--telemetry-addr $(TELEMETRY_ADDR)) \
	$(if $(ADMIN_ADDR),--admin-addr $(ADMIN_ADDR)) \
	$(ARGS)

.PHONY: help build run run-as-local-tls run-as-prod version cli test bench lint \
        lab-up lab-down lab-get-idp-config lab-get-idp-jwt lab-demo lab-demo-print \
        lab-demo-interactive lab-run-demo run-as-docker run-as-docker-dev \
        audit-verify check-seams check-core-deps check-supply-chain check

# ---------------------------------------------------------------------------------------------
# Build and run
# ---------------------------------------------------------------------------------------------

# Build every component.
#
#   make build
#   make build PKG=pic-x-core
#   make build RELEASE=1
#   make build ARGS='--all-features'
#
#   PKG      Build only this workspace crate. Default: the whole workspace.
#   RELEASE  Build with the release profile when set to any value. Default: unset.
#   ARGS     Extra flags appended verbatim to `cargo build`. Default: empty.
build: ## Build every component.
	cargo build $(scope) $(profile) $(ARGS)

# Start the server against config.local.yaml.
#
# It is a local development run: loopback only, no TLS, readable logs and `.volume/` created on
# first start. Serving is the binary's default action, so the direct form is `pic-x <CONFIG>`.
#
# See docs/start-server.md for the full startup guide.
#
#   make run
#   make run CONFIG=./my-config.yaml
#   make run LOG_LEVEL=trace
#   make run ADMIN_ADDR=127.0.0.1:6000
#
#   CONFIG            Configuration file. Default: config.local.yaml.
#   LOG_LEVEL         error, warn, info, debug, or trace. Default: whatever CONFIG says.
#   LOG_FORMAT        json or terminal. Default: whatever CONFIG says.
#   RELEASE           Run the release build when set to any value. Default: unset.
#   PUBLIC_HTTP_ADDR  Override the public listen address. Default: from CONFIG.
#   TELEMETRY_ADDR    Override the telemetry listen address. Default: from CONFIG.
#   ADMIN_ADDR        Override the admin listen address. Default: from CONFIG.
#   ARGS              Extra flags appended verbatim to the invocation. Default: empty.
run: ## Run the server locally — everything on, nothing to set up first.
	$(call serve_cmd,$(if $(CONFIG),$(CONFIG),config.local.yaml))

# Start the server against config.local-tls.yaml.
#
# The first start generates a local authority, a server certificate and an operator client
# certificate under `.volume/tls/`. Once it is up:
#
#   curl --cacert .volume/tls/ca.pem https://localhost:7556/.well-known/jwks.json
#
#   grpcurl -cacert .volume/tls/ca.pem \
#           -cert .volume/tls/client.pem -key .volume/tls/client.key \
#           -import-path crates/pic-x-admin/proto -proto picx/admin/v1/admin.proto \
#           localhost:7557 picx.admin.v1.Admin/GetVersion
#
# Parameters: the same as `make run`, with CONFIG defaulting to config.local-tls.yaml.
run-as-local-tls: ## The same local run, over TLS with mutual TLS on the administrative surface.
	$(call serve_cmd,$(if $(CONFIG),$(CONFIG),config.local-tls.yaml))

# Start the server against config.prod.yaml, which is the file copied into the container image.
#
# It is production-shaped and should fail until the required TLS material, admin client CA and
# audit pseudonymisation secret exist. That is intentional: production config does not mint trust
# material for itself.
#
# It also writes to /var/lib/pic-x, which on a developer machine usually does not exist, so
#
#   make run-as-prod CONFIG=./my-config.yaml
#
# is the usual way to try a real configuration of your own.
#
# Parameters: the same as `make run`, with CONFIG defaulting to config.prod.yaml.
# See docs/start-server.md and docs/docker.md for the operational notes.
run-as-prod: ## Run the server as a deployment runs it — the file the image ships.
	$(call serve_cmd,$(if $(CONFIG),$(CONFIG),config.prod.yaml))

# Report the product version.
version: ## Report the product version.
	cargo run $(profile) --bin pic-x -- version

# Run the pic-x binary with arbitrary arguments.
#
# This is the escape hatch for invocations the named targets do not cover — a command added later,
# or a flag combination worth trying once. `make run` stays the way to start the server.
#
#   make cli ARGS=--help
#   make cli ARGS=version
#   make cli ARGS='./my-config.yaml --admin-addr 0.0.0.0:6000'
#   make cli RELEASE=1 ARGS=--version
#
#   ARGS     Arguments passed verbatim to the binary. Default: empty, which prints usage.
#   RELEASE  Run the release build when set to any value. Default: unset.
cli: ## Run the pic-x binary with arbitrary arguments.
	cargo run $(profile) --bin pic-x -- $(ARGS)

# ---------------------------------------------------------------------------------------------
# Tests, benchmarks, lint
# ---------------------------------------------------------------------------------------------

# Run the unit and use-case tests.
#
#   make test
#   make test PKG=pic-x-core
#   make test FILTER=test_validate
#   make test FILTER=test_validate NOCAPTURE=1
#   make test RELEASE=1 ARGS='--all-features'
#
#   PKG        Test only this workspace crate. Default: the whole workspace.
#   FILTER     Only run tests whose name contains this string. Default: all tests.
#   NOCAPTURE  Show test stdout/stderr when set to any value. Default: unset.
#   RELEASE    Test the release profile when set to any value. Default: unset.
#   FEATURES   Feature selection. Default: --all-features, so nothing is silently skipped —
#              `pic-x-std` keeps `provision` outside its default set, and a plain `cargo test`
#              would never compile the tests that cover it.
#   ARGS       Extra flags appended verbatim to `cargo test`. Default: empty.
test: ## Run the unit and use-case tests.
	cargo test $(scope) $(FEATURES) $(profile) $(ARGS) $(FILTER) $(if $(NOCAPTURE),-- --nocapture)

# Run the benchmarks.
#
#   make bench
#   make bench BENCH=server_host
#   make bench PKG=pic-x-server
#   make bench ARGS='--all-features'
#
#   PKG     Benchmark only this workspace crate. Default: the whole workspace.
#   BENCH   Only run this benchmark target (`--bench <name>`). Default: all targets.
#   FILTER  Only run benchmarks whose name contains this string. Default: all benchmarks.
#   ARGS    Extra flags appended verbatim to `cargo bench`. Default: empty.
bench: ## Run the benchmarks.
	cargo bench $(scope) $(if $(BENCH),--bench $(BENCH)) $(ARGS) $(FILTER)

# Run clippy over every crate and target, failing on any warning.
#
#   make lint
#   make lint PKG=pic-x-server
#   make lint ARGS=--fix
#
#   PKG   Lint only this workspace crate. Default: the whole workspace.
#   ARGS  Extra flags appended verbatim to `cargo clippy`. Default: empty.
lint: ## Run clippy over every crate and target.
	cargo clippy $(scope) --all-targets --all-features $(ARGS) -- -D warnings

# ---------------------------------------------------------------------------------------------
# The local lab
# ---------------------------------------------------------------------------------------------

# Start the local compose stack. It imports the `acme-idp` example IdP realm into Keycloak,
# exposes Keycloak on localhost:18080, builds PIC-X from the local source with config.lab.yaml,
# and builds the local trust-lab REST service on localhost:17080.
#
# See docs/keycloak.md for credentials and lab commands.
lab-up: ## Start the local Docker Compose lab.
# One directory per service, so the lab's state can be read from the host while it runs.
	@mkdir -p .volume-docker-compose/pic-x .volume-docker-compose/trust-lab .volume-docker-compose/keycloak
	@chmod -R a+rwX .volume-docker-compose
	@docker compose -f docker-compose.lab.yml up --build -d

# Stop and remove the local compose stack.
lab-down: ## Stop the local Docker Compose lab.
	@docker compose -f docker-compose.lab.yml down

# Request the OpenID Connect well-known configuration from the local Keycloak lab and print the
# raw JSON response. Start the lab first with `make lab-up`.
#
#   KEYCLOAK_URL    Base URL. Default: http://localhost:18080.
#   KEYCLOAK_REALM  Realm name. Default: acme-idp.
lab-get-idp-config: ## Print the local Keycloak IdP well-known configuration.
	@curl -fsS "$(KEYCLOAK_URL)/realms/$(KEYCLOAK_REALM)/.well-known/openid-configuration"

# Request an access token from the local Keycloak lab and print only the JWT.
# Start the lab first with `make lab-up`.
#
#   make lab-get-idp-jwt
#   make lab-get-idp-jwt KEYCLOAK_USERNAME=alice KEYCLOAK_PASSWORD=alice-password
#
#   KEYCLOAK_URL            Base URL. Default: http://localhost:18080.
#   KEYCLOAK_REALM          Realm name. Default: acme-idp.
#   KEYCLOAK_CLIENT_ID      Client ID. Default: acme-idp-client.
#   KEYCLOAK_CLIENT_SECRET  Client secret. Default: acme-idp-client-secret.
#   KEYCLOAK_USERNAME       Username. Default: alice.
#   KEYCLOAK_PASSWORD       Password. Default: alice-password.
lab-get-idp-jwt: ## Print a JWT from the local Keycloak lab.
	@set -o pipefail; curl -fsS -X POST \
		"$(KEYCLOAK_URL)/realms/$(KEYCLOAK_REALM)/protocol/openid-connect/token" \
		-H "Content-Type: application/x-www-form-urlencoded" \
		--data-urlencode "grant_type=password" \
		--data-urlencode "client_id=$(KEYCLOAK_CLIENT_ID)" \
		--data-urlencode "client_secret=$(KEYCLOAK_CLIENT_SECRET)" \
		--data-urlencode "username=$(KEYCLOAK_USERNAME)" \
		--data-urlencode "password=$(KEYCLOAK_PASSWORD)" \
		| sed -n 's/.*"access_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'

# Run the didactic lab walkthrough. It checks that Keycloak, PIC-X and trust-lab are reachable,
# requests an example IdP token and prints the token with a short explanation of what happened.
#
# Start the lab first with `make lab-up`.
#
#   make lab-demo
#   make lab-demo ARGS=--print-tokens
#   make lab-demo ARGS=--interactive
lab-demo: ## Run the local lab walkthrough.
	@$(PYTHON) trust-lab/scripts/pic-x-demo.py $(ARGS)

# Run the didactic lab walkthrough with token and PIC artifact inspection enabled.
lab-demo-print: ## Run the local lab walkthrough and print decoded token/PIC artifact values.
	@$(PYTHON) trust-lab/scripts/pic-x-demo.py --print-tokens

# Run the didactic lab walkthrough in guided mode. It pauses before each exchange, prints the
# OAuth access token, PIC Token JWTs, Continuity/PCA payloads, execution contract, the real HTTP
# requests and responses, and the local workload process outputs used by the exchanges.
lab-demo-interactive: ## Run the local lab walkthrough step by step with HTTP packet traces.
	@$(PYTHON) trust-lab/scripts/pic-x-demo.py --interactive

lab-run-demo: lab-demo ## Alias for lab-demo.

# ---------------------------------------------------------------------------------------------
# The container image
# ---------------------------------------------------------------------------------------------

# Build the image and run it against the configuration it runs by default: config.prod.yaml,
# copied to /etc/pic-x/config.yaml.
#
# With an empty volume this should fail. Production config requires TLS material, an admin client
# CA and a pseudonymisation secret supplied from outside the process:
#
#   pic-x: validating the configuration loaded from /etc/pic-x/config.yaml: validating the public
#   TLS material: the TLS certificate /var/lib/pic-x/tls/server.pem is not a readable file
#
# For a container that starts with nothing prepared, use `make run-as-docker-dev`. It is the same
# image and gives up transport security to get there.
#
#   make run-as-docker
#   make run-as-docker VOLUME=/tmp/pic-x-docker
#   make run-as-docker TAG=pic-x:experiment
#
#   TAG     Image tag to build and run. Default: pic-x:local.
#   VOLUME  Host directory mounted as the volume. Default: .volume-docker.
#
# See docs/docker.md for required files, permissions and the local production-shaped demo.
run-as-docker: ## Build the image and run what it ships — production, which refuses to start unprepared.
run-as-docker: VOLUME_DIR = $(if $(VOLUME),$(VOLUME),.volume-docker)
run-as-docker:
	docker build --tag $(TAG) .
	mkdir -p $(VOLUME_DIR)
	docker run --rm --init \
		--publish 7556:7556 --publish 7557:7557 --publish 7558:7558 \
		--volume "$(call host_path,$(VOLUME_DIR)):/var/lib/pic-x" \
		$(TAG)

# Build the image and run it against config.dev.yaml, which the same image ships at
# /etc/pic-x/config.dev.yaml.
#
# It starts from an empty volume and generates development material on first start. It has no TLS
# and no admin client certificate; do not run it where the ports are reachable by somebody else.
#
# Once it is up:
#
#   curl http://localhost:7556/.well-known/jwks.json
#   curl http://localhost:7558/metrics
#
#   grpcurl -plaintext \
#           -import-path crates/pic-x-admin/proto -proto picx/admin/v1/admin.proto \
#           localhost:7557 picx.admin.v1.Admin/GetVersion
#
#   make run-as-docker-dev
#   make run-as-docker-dev VOLUME=/tmp/pic-x-docker-dev
#
# Parameters: the same as `make run-as-docker`, with VOLUME defaulting to .volume-docker-dev.
# See docs/docker.md for the container guide.
run-as-docker-dev: ## Build the image and run it with nothing to prepare — no transport security.
run-as-docker-dev: VOLUME_DIR = $(if $(VOLUME),$(VOLUME),.volume-docker-dev)
run-as-docker-dev:
	docker build --tag $(TAG) .
	mkdir -p $(VOLUME_DIR)
# The mount point, and nothing inside it: the container writes as uid 65532 and needs the
# directory. Recursing would loosen the secret it wrote on the last run, and the secret store
# would then refuse to read it — correctly.
	chmod a+rwX $(VOLUME_DIR)
	docker run --rm --init \
		--publish 7556:7556 --publish 7557:7557 --publish 7558:7558 \
		--volume "$(call host_path,$(VOLUME_DIR)):/var/lib/pic-x" \
		$(TAG) /etc/pic-x/config.dev.yaml

# ---------------------------------------------------------------------------------------------
# Audit and the pipeline checks
# ---------------------------------------------------------------------------------------------

# Read the file audit trail and check record digests, sequence continuity, day boundaries and
# seals.
#
# With KEYS, each seal's signature is checked too. Point it at a key set you trust — checking a
# seal against keys taken from the machine under suspicion checks a signature against a key the
# same attacker could have replaced:
#
#   make audit-verify KEYS=./trusted.jwks
#
#   make audit-verify
#   make audit-verify VOLUME=/tmp/pic-x
#   make audit-verify KEYS=./trusted.jwks
#
#   VOLUME  Where everything lives. Default: .volume beside the repository.
#   KEYS    A JWKS document to check the seals' signatures against. Default: unset.
#
# See docs/audit.md for the audit guide.
audit-verify: ## Check that nothing in the audit trail has been altered. (task audit:verify)
audit-verify: VOLUME_DIR = $(if $(VOLUME),$(VOLUME),.volume)
audit-verify:
	cargo run --quiet --bin pic-x -- audit verify --directory $(VOLUME_DIR)/audit \
		$(if $(KEYS),--keys $(KEYS))

# Check that only the binary constructs swappable collaborators.
#
# Every crate here receives its collaborators instead of resolving them, which is what lets
# another binary reuse these crates and replace the parts it needs. Nothing in the type system
# enforces that, so it is checked here.
check-seams: ## Check that only the binary constructs swappable collaborators. (task check:seams)
	./scripts/check-composition-root.sh

# Check that pic-x-core keeps its dependency list minimal.
#
# Every crate depends on pic-x-core, including the ones a downstream build writes. Whatever lands
# in its dependency list lands in all of them, so the list is an allowlist.
check-core-deps: ## Check that pic-x-core keeps its dependency list minimal. (task check:core-deps)
	./scripts/check-core-dependencies.sh

# Check every crate this workspace pulls in: known advisories, unmaintained crates, licences
# outside the permissive set, and anything from a registry nobody named.
#
# The rules live in deny.toml, and each of them exists for a reason written down beside it. An
# exception belongs in that file with an id and a justification, so it is reviewable rather than
# invisible.
check-supply-chain: ## Check the dependency tree for advisories, licences and unknown sources. (task check:supply-chain)
	cargo deny check

# Run lint, both structural checks, the supply-chain gates and the test suite, in that order.
# Recursive on purpose: prerequisites carry no order, and this list is an order.
check: ## Run every check the pipeline runs.
	$(MAKE) lint
	$(MAKE) check-seams
	$(MAKE) check-core-deps
	$(MAKE) check-supply-chain
	$(MAKE) test

# ---------------------------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------------------------

# The one-line description beside each target is what `make help` prints. The block above each
# target is the long form — `task --summary <name>` has no counterpart here, so it is read in
# place, in this file.
help: ## Show this help.
	@printf 'PIC-X — make targets\n\n'
	@printf 'Usage: make <target> [VAR=value ...]\n\n'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_.-]+:.*?## /{printf "  %-22s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@printf '\nEvery parameter is set on the command line, e.g. make test PKG=pic-x-core FILTER=validate\n'
	@printf 'The long form of each target is the comment block above it in the Makefile.\n'
