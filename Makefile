
BINARY_NAME=ecdsa-go

build:
	@go build -o bin/$(BINARY_NAME) -v

run:
	@./bin/$(BINARY_NAME)

test:
	@go test -v ./...

clean:
	@go clean
	@rm -f bin/$(BINARY_NAME)

.PHONY: build run test clean