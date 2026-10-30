# Pin to the locally installed Go toolchain so `make` never triggers a
# toolchain download on a throwaway VPS.
export GOTOOLCHAIN := local

BIN ?= srt
PREFIX ?= /usr/local

.PHONY: build install go-install test vet clean

build:
	go build -trimpath -ldflags="-s -w" -o $(BIN) ./cmd/srt

install: build
	install -m 0755 $(BIN) $(PREFIX)/bin/$(BIN)

# Installs into $(go env GOBIN) or $(go env GOPATH)/bin -- make sure that is on PATH.
go-install:
	go install -trimpath -ldflags="-s -w" ./cmd/srt

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -f $(BIN)
