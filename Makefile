VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
CODENAME ?=
LDFLAGS := -s -w -X main.version=$(VERSION) -X 'main.codename=$(CODENAME)'

.PHONY: build test vet linux
build:
	go build -ldflags "$(LDFLAGS)" -o dist/switchboard ./cmd/switchboard
linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o dist/switchboard-linux-amd64 ./cmd/switchboard
test:
	go test -race ./...
vet:
	go vet ./...
	test -z "$$(gofmt -l .)"
