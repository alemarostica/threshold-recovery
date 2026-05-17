ROOT_DIR=.
CLIENT_DIR=$(ROOT_DIR)/client_dir
SERVER_BINARY_NAME=$(ROOT_DIR)/server
CLIENT_BINARY_NAME=$(CLIENT_DIR)/client
SERVER_SOURCE=./cmd/server/main.go
CLIENT_SOURCE_DIR=./cmd/client
CERT_DIR=./certs
SERVER_CRT=$(CERT_DIR)/server.crt
SERVER_KEY=$(CERT_DIR)/server.key

.PHONY: build-all build-server run-server build-client clean clean-all prepare-deps

build-all: prepare-deps $(SERVER_CRT) build-server build-client

prepare-deps:
	@echo "Fetching dependencies..."
	go mod tidy
	go mod download

$(SERVER_CRT):
	@echo "Generating SSL certificates..."
	mkdir -p $(CERT_DIR)
	openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=localhost"

build-server: prepare-deps $(SERVER_CRT)
	@echo "Building the server..."
	go build -o $(SERVER_BINARY_NAME) $(SERVER_SOURCE)

run-server: prepare-deps $(SERVER_CRT)
	@echo "Starting the server..."
	go run $(SERVER_SOURCE)

build-client: prepare-deps $(SERVER_CRT)
	@echo "Building the client..."
	go build -o $(CLIENT_BINARY_NAME) $(CLIENT_SOURCE_DIR)
	mkdir $(CLIENT_DIR)/1 $(CLIENT_DIR)/2 $(CLIENT_DIR)/3

clean:
	@echo "Cleaning executables..."
	rm -f $(SERVER_BINARY_NAME)
	rm -f $(CLIENT_BINARY_NAME)
	@echo "Done."

clean-all:
	@echo "Cleaning executables and directories..."
	rm -f $(SERVER_BINARY_NAME)
	rm -f $(CLIENT_BINARY_NAME)
	rm -fr $(CLIENT_DIR)
	rm -fr ./data/
	@echo "Done."
