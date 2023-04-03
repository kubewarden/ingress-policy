module github.com/kubewarden/ingress-policy

go 1.20

require (
	github.com/deckarep/golang-set/v2 v2.3.0
	github.com/kubewarden/gjson v1.7.2
	github.com/kubewarden/k8s-objects v1.24.0-kw7
	github.com/kubewarden/policy-sdk-go v0.3.0
	github.com/mailru/easyjson v0.7.7
	github.com/wapc/wapc-guest-tinygo v0.3.3
)

replace github.com/go-openapi/strfmt => github.com/kubewarden/strfmt v0.1.2

require (
	github.com/go-openapi/strfmt v0.21.3 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/tidwall/match v1.0.3 // indirect
	github.com/tidwall/pretty v1.0.2 // indirect
)
