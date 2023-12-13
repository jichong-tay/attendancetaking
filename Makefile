build:
	@go build -o bin/start

run: build
	./bin/start

