BINARY_NAME=launch-server
CLIENT_NAME=recovery-client
MAIN_PATH=./cmd/server/main.go

.PHONY: all build run clean

all: build

build:
	@echo "Building the server..."
	go build -o $(BINARY_NAME) $(MAIN_PATH)

run:
	@echo "Starting the server..."
	go run $(MAIN_PATH)

client:
	@echo "Running simulation client..."
	go run cmd/client/main.go

clean:
	@echo "Cleaning up..."
	rm -f $(BINARY_NAME)
	## rm -fr ./data/*.json
	@echo "Done."
