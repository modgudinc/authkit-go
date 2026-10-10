GO_CACHE ?= /tmp/authkit-go-go-cache
GOLANGCI_LINT_CACHE ?= /tmp/authkit-go-golangci-lint-cache
IDENTITY_TEST_DATABASE_URL ?= postgres://authkit_test:authkit_test@localhost:55432/authkit_test?sslmode=disable

.PHONY: test
test:
	GOCACHE=$(GO_CACHE) go test -race -count=1 ./...

.PHONY: lint
lint:
	GOCACHE=$(GO_CACHE) GOLANGCI_LINT_CACHE=$(GOLANGCI_LINT_CACHE) golangci-lint run

.PHONY: test-integration
test-integration:
	IDENTITY_TEST_DATABASE_URL="$(IDENTITY_TEST_DATABASE_URL)" GOCACHE=$(GO_CACHE) go test -race -count=1 -p 1 -tags=integration ./...

.PHONY: postgres-up
postgres-up:
	docker compose up -d --wait postgres

.PHONY: postgres-down
postgres-down:
	docker compose down

.PHONY: postgres-reset
postgres-reset:
	docker compose down -v
	docker compose up -d --wait postgres
