Kubewarden policy that allows to restrict ingress resources.

# What the policy allows to restrict

The policy configuration allows to set several properties:

* `requireTLS`: `boolean`
  * Whether the `spec` for ingresses resources has to include a `tls`
    attribute that include all hosts defined in the `.spec.rules`
    attribute of the ingress resource. If any of the hosts defined in
    `.spec.rules` is not listed inside `spec.tls` the policy will
    reject the ingress resource.

* `allowPorts`: `[<int>]`
  * List of allowed ports inside
    `.spec.rules.paths.backend.service.port`. If this array contains
    at least one port, any other port will be rejected.

* `denyPorts`: `[<int>]`
  * List of denied ports inside
    `.spec.rules.paths.backend.service.port`. If any port matches a
    port on this array, the ingress resource will be rejected,
    otherwise it will be accepted.

If `allowPorts` and `denyPorts` are provided together (and are not
empty), `denyPorts` is prioritized.

## Examples

* Require TLS for all hosts provided in ingress:

```json
{
  "requireTLS": true
}

```

* Require TLS for all hosts provided in ingress, and disallow port 80:

```json
{
  "requireTLS": true,
  "denyPorts": [80]
}

```

* Require TLS for all hosts provided in ingress, and only allow port
  443:

```json
{
  "requireTLS": true,
  "allowPorts": [443]
}

```

# Building

The policy must be built using a version of [TinyGo](https://github.com/tinygo-org/tinygo)
major than `0.17.0`.

This is automatically done using this command:

```shell
make build
```

This will trigger a build using docker.

# Testing

The native Go tests must be run using the official Go toolkit (not TinyGo):

```shell
make test
```

The WebAssembly binary produced by the `make build` process can be tested using
the following command:

```shell
make e2e-tests
```

This command requires the following binaries to be installed on your system:

  * Kubewarden policy-testdrive: it can be downloaded by [this page](https://github.com/kubewarden/policy-server/releases)
  * [bats](https://github.com/sstephenson/bats), the Bash Automated Testing System
