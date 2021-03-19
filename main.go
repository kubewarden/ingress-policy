package main

import (
	"fmt"
	"strconv"

	"github.com/buger/jsonparser"
	chimera "github.com/chimera-kube/policy-sdk-go"
	wapc "github.com/wapc/wapc-guest-tinygo"
)

func slicesAreEqualOrderInsensitive(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	elementsA, elementsB := map[string]struct{}{}, map[string]struct{}{}
	for _, elementA := range a {
		elementsA[elementA] = struct{}{}
	}
	for _, elementB := range b {
		elementsB[elementB] = struct{}{}
		if _, ok := elementsA[elementB]; !ok {
			return false
		}
	}
	for _, elementA := range a {
		if _, ok := elementsB[elementA]; !ok {
			return false
		}
	}
	return true
}

func ingressPorts(payload []byte) []uint16 {
	res := []uint16{}
	jsonparser.ArrayEach(
		payload,
		func(rule []byte, _ jsonparser.ValueType, _ int, _ error) {
			jsonparser.ArrayEach(
				rule,
				func(path []byte, _ jsonparser.ValueType, _ int, _ error) {
					backendPort, _, _, _ := jsonparser.Get(path, "backend", "service", "port")
					if port, err := strconv.ParseUint(string(backendPort), 10, 16); err == nil {
						res = append(res, uint16(port))
					}
				},
				"http", "paths",
			)
		},
		"request", "request", "object", "spec", "rules",
	)
	return res
}

func validate(payload []byte) ([]byte, error) {
	settings, _, _, _ := jsonparser.Get(payload, "settings")
	tlsHosts, rulesHosts := []string{}, []string{}
	jsonparser.ArrayEach(
		payload,
		func(value []byte, _ jsonparser.ValueType, _ int, _ error) {
			hosts := []string{}
			jsonparser.ArrayEach(
				value,
				func(value []byte, _ jsonparser.ValueType, _ int, _ error) {
					hosts = append(hosts, string(value))
				},
				"hosts",
			)
			tlsHosts = append(tlsHosts, hosts...)
		},
		"request", "request", "object", "spec", "tls",
	)
	jsonparser.ArrayEach(
		payload,
		func(value []byte, _ jsonparser.ValueType, _ int, _ error) {
			host, _, _, _ := jsonparser.Get(value, "host")
			rulesHosts = append(rulesHosts, string(host))
		},
		"request", "request", "object", "spec", "rules",
	)
	if settingsRequireTLS(settings) {
		if !slicesAreEqualOrderInsensitive(tlsHosts, rulesHosts) {
			return chimera.RejectRequest(chimera.Message("not all hosts have TLS configuration"), chimera.NoCode)
		}
	}
	ingressPorts := ingressPorts(payload)
	settingsDenyPorts := settingsDenyPorts(settings)
	if len(settingsDenyPorts) > 0 {
		for _, ingressPort := range ingressPorts {
			if _, ok := settingsDenyPorts[ingressPort]; ok {
				return chimera.RejectRequest(chimera.Message(fmt.Sprintf("port %d is in the list of denied ports", ingressPort)), chimera.NoCode)
			}
		}
	}
	settingsAllowPorts := settingsAllowPorts(settings)
	if len(settingsAllowPorts) > 0 {
		for _, ingressPort := range ingressPorts {
			if _, ok := settingsAllowPorts[ingressPort]; !ok {
				return chimera.RejectRequest(chimera.Message(fmt.Sprintf("port %d is not in the list of allowed ports", ingressPort)), chimera.NoCode)
			}
		}
	}
	return chimera.AcceptRequest()
}

func settingsRequireTLS(payload []byte) bool {
	requireTLS, _, _, _ := jsonparser.Get(payload, "requireTLS")
	requireTLSBool, err := strconv.ParseBool(string(requireTLS))
	if err != nil {
		return false
	}
	return requireTLSBool
}

func settingsAllowPorts(payload []byte) map[uint16]struct{} {
	allowPorts := map[uint16]struct{}{}
	jsonparser.ArrayEach(
		payload,
		func(value []byte, _ jsonparser.ValueType, _ int, _ error) {
			if allowPort, err := strconv.ParseUint(string(value), 10, 16); err == nil {
				allowPorts[uint16(allowPort)] = struct{}{}
			}
		},
		"allowPorts",
	)
	return allowPorts
}

func settingsDenyPorts(payload []byte) map[uint16]struct{} {
	denyPorts := map[uint16]struct{}{}
	jsonparser.ArrayEach(
		payload,
		func(value []byte, _ jsonparser.ValueType, _ int, _ error) {
			if denyPort, err := strconv.ParseUint(string(value), 10, 16); err == nil {
				denyPorts[uint16(denyPort)] = struct{}{}
			}
		},
		"denyPorts",
	)
	return denyPorts
}

func main() {
	wapc.RegisterFunctions(wapc.Functions{
		"validate": validate,
	})
}
