wasm: go.mod go.sum *.go
	docker run --rm -v ${PWD}:/src -w /src ghcr.io/kubewarden/tinygo/tinygo-dev:w14-2021 tinygo build -o policy.wasm -target=wasi -no-debug .

test:
	go test -v

e2e-tests:
	bats e2e.bats

.PHONY: clean
clean:
	rm policy.wasm
