.PHONY: run gendoc build tests docker-latest

BUILD_DATE 	:= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
GIT_COMMIT 	:= $(shell git rev-parse HEAD)
GIT_STATE 	:= $(shell test -n "`git status --porcelain`" && echo "dirty" || echo "clean")
VERSION 	?= dev

run:
	go run ./cmd/argane/main.go $(ARGS)

gendoc:
	rm -r ./www/src/content/docs/commands/*
	rm -r ./www/src/content/docs/rules/*
	go run ./scripts/gendoc/

build:
	go build -ldflags "\
		-s -w \
		-X 'github.com/kkrypt0nn/argane/internal/buildinfo.Version=$(VERSION)' \
		-X 'github.com/kkrypt0nn/argane/internal/buildinfo.BuildDate=$(BUILD_DATE)' \
		-X 'github.com/kkrypt0nn/argane/internal/buildinfo.GitCommit=$(GIT_COMMIT) ($(GIT_STATE))'" \
		-o ./dist/argane ./cmd/argane/main.go

tests:
	go test github.com/kkrypt0nn/argane/internal/policies/tests -v
