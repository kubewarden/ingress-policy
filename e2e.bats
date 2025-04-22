#!/usr/bin/env bats

@test "reject because required TLS failure" {
  run kwctl run annotated-policy.wasm -r test_data/ingress-wildcard.json --settings-json '{"requireTLS": true}'

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request rejected
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*false') -ne 0 ]
  [ $(expr "$output" : '.*Not all hosts have TLS enabled.*') -ne 0 ]

}

@test "reject because not allowed port is used" {
  run kwctl run annotated-policy.wasm -r test_data/ingress-wildcard.json --settings-json '{"allowPorts": [80]}'

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request rejected
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*false') -ne 0 ]
  [ $(expr "$output" : '.*these ports are not on the allowed list: Set{3000}.*') -ne 0 ]
}

@test "reject because not denied port is used" {
  run kwctl run annotated-policy.wasm -r test_data/ingress-wildcard.json --settings-json '{"denyPorts": [3000]}'

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request rejected
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*false') -ne 0 ]
  [ $(expr "$output" : '.*these ports are explicitly denied: Set{3000}.*') -ne 0 ]
}

@test "reject because invalid settings" {
  run kwctl run annotated-policy.wasm -r test_data/ingress-wildcard.json --settings-json '{"allowPorts": [80, 3000], "denyPorts": [3000]}'

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # settings validation fails
  [ "$status" -eq 1 ]
}

@test "accept" {
  run kwctl run annotated-policy.wasm -r test_data/single-backend-with-tls-termination.json --settings-json '{"requireTLS": true, "denyPorts": [3000]}'
  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request accepted
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*true') -ne 0 ]
}
