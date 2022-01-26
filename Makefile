.PHONY: policy.wasm
policy.wasm: go.mod go.sum *.go
	docker run --rm -v ${PWD}:/src -w /src tinygo/tinygo:0.18.0 tinygo build -o policy.wasm -target=wasi -no-debug .

annotated-policy.wasm: policy.wasm
	kwctl annotate -m metadata.yml -o annotated-policy.wasm policy.wasm

.PHONY: test
test:
	go test -v

.PHONY: e2e-tests
e2e-tests: annotated-policy.wasm
	bats e2e.bats

.PHONY: clean
clean:
	rm policy.wasm
