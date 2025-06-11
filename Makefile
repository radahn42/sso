CONFIG_FILE_LOCAL = ./config/local.yaml
CONFIG_FILE_TESTS = ./config/local_tests.yaml
SSO_MAIN = ./cmd/sso/main.go
BIN_PATH = ./tmp/main.exe

build:
	go build -o $(BIN_PATH) ./cmd/sso

run:
	$(BIN_PATH) --config=$(CONFIG_FILE)

run-dev:
	air

rebuild: build run
