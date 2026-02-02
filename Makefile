ROOT_DIR=.
CLIENT_DIR=$(ROOT_DIR)/client_dir
SERVER_BINARY_NAME=$(ROOT_DIR)/server
CLIENT_BINARY_NAME=$(CLIENT_DIR)/client
SERVER_SOURCE=./cmd/server/main.go
CLIENT_SOURCE=./cmd/client/main.go

.PHONY: build-all build-server run-server build-client clean

build-all: build-server build-client

build-server:
	@echo "Building the server..."
	go build -o $(SERVER_BINARY_NAME) $(SERVER_SOURCE)

run-server:
	@echo "Starting the server..."
	go run $(SERVER_SOURCE)

build-client:
	@echo "Building the client..."
	go build -o $(CLIENT_BINARY_NAME) $(CLIENT_SOURCE)

clean:
	@echo "Cleaning up..."
	rm -f $(SERVER_BINARY_NAME)
	rm -f $(CLIENT_BINARY_NAME)
	rm -fr $(CLIENT_DIR)
	## rm -fr ./data/*.json
	@echo "Done."
