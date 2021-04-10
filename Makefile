wasm: go.mod go.sum *.go
	docker run --rm -v ${PWD}:/src -w /src tinygo/tinygo-dev:latest tinygo build -o ingress-policy.wasm -target=wasi -no-debug .

test:
	go test -v

e2e-tests:
	bats e2e.bats

.PHONY: clean
clean:
	rm ingress-policy.wasm
