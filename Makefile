wasm: go.mod go.sum *.go
	docker run --rm -v ${PWD}:/src -w /src tinygo/tinygo:0.17.0 tinygo build -o ingress-policy.wasm -target=wasi -no-debug .

test:
	policy-testdrive --policy ingress-policy.wasm  --request-file admission-review.sample.json --settings '{"requireTLS": true, "allowPorts": [443], "denyPorts": []}'

.PHONY: clean
clean:
	rm ingress-policy.wasm
