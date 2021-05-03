#!/usr/bin/env bats

@test "reject because required TLS failure" {
  run policy-testdrive -p policy.wasm -r test_data/ingress-wildcard.json -s '{"requireTLS": true}'

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # settings validation passed
  [[ "$output" == *"valid: true"* ]]

  # request rejected
  [[ "$output" == *"allowed: false"* ]]
  [[ "$output" == *"Not all hosts have TLS enabled"* ]]
}

@test "reject because not allowed port is used" {
  run policy-testdrive -p policy.wasm -r test_data/ingress-wildcard.json -s '{"allowPorts": [80]}'

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # settings validation passed
  [[ "$output" == *"valid: true"* ]]

  # request rejected
  [[ "$output" == *"allowed: false"* ]]
  [[ "$output" == *"These ports are not on the allowed list: Set{3000}"* ]]
}

@test "reject because not denied port is used" {
  run policy-testdrive -p policy.wasm -r test_data/ingress-wildcard.json -s '{"denyPorts": [3000]}'

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # settings validation passed
  [[ "$output" == *"valid: true"* ]]

  # request rejected
  [[ "$output" == *"allowed: false"* ]]
  [[ "$output" == *"These ports are explicitly denied: Set{3000}"* ]]
}

@test "reject because invalid settings" {
  run policy-testdrive -p policy.wasm -r test_data/ingress-wildcard.json -s '{"allowPorts": [80, 3000], "denyPorts": [3000]}'

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # settings validation fails
  [[ "$output" == *"valid: false"* ]]
}

@test "accept" {
  run policy-testdrive -p policy.wasm -r test_data/single-backend-with-tls-termination.json -s '{"requireTLS": true, "denyPorts": [3000]}'
  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # settings validation passed
  [[ "$output" == *"valid: true"* ]]

  # request accepted
  [[ "$output" == *"allowed: true"* ]]
}
