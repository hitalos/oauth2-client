include .env
export $(shell sed 's/=.*//' .env)

build:
	go build -ldflags '-s -w' -o dist/server ./cmd/server

run:
	go run ./cmd/server

lint:
	golangci-lint run ./...

clean:
	rm -rf dist

.PHONY: build run lint clean