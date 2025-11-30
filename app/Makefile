.PHONY: help run build test clean migrate

help:
	@echo "CheckTheBox Development Commands"
	@echo "================================="
	@echo "make run      - Run the application"
	@echo "make build    - Build the application"
	@echo "make test     - Run tests"
	@echo "make clean    - Clean build artifacts"
	@echo "make migrate  - Run database migrations"

run:
	go run ./cmd/server

build:
	go build -o bin/checkthebox ./cmd/server

test:
	go test -v ./...

clean:
	rm -rf bin/

migrate:
	psql $$DATABASE_URL -f migrations/init.sql

