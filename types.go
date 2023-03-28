package main

type RawSettings struct {
	RequireTls bool     `json:"requireTLS"`
	AllowPorts []uint64 `json:"allowPorts"`
	DenyPorts  []uint64 `json:"denyPorts"`
}
