BIN := bin/ip-traffic-exporter

.PHONY: all generate build build-arm64 test test-bin clean

all: build

# Needs clang. The generated files are checked in, so plain builds don't.
generate:
	go generate ./...

build:
	CGO_ENABLED=0 go build -trimpath -o $(BIN) .

build-arm64:
	CGO_ENABLED=0 GOARCH=arm64 go build -trimpath -o $(BIN)-arm64 .

# Probe tests are skipped without CAP_BPF/CAP_NET_ADMIN.
test:
	go vet ./...
	go test ./...

# Test binary to copy to and run as root on a target host.
test-bin:
	CGO_ENABLED=0 go test -c -o bin/probe.test ./internal/probe

clean:
	rm -rf bin
