package main

import (
	"fmt"
	"strconv"

	"github.com/chimera-kube/gjson"
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
	result := gjson.Get(string(payload), "request.request.object.spec.rules.#.http.paths.#.backend.service.port")
	for _, rule := range result.Array() {
		for _, port := range rule.Array() {
			port, err := strconv.ParseInt(port.String(), 10, 16)
			if err != nil {
				continue
			}
			res = append(res, uint16(port))
		}
	}
	return res
}

func validate(payload []byte) ([]byte, error) {
	tlsHosts, rulesHosts := []string{}, []string{}
	for _, host := range gjson.Get(string(payload), "request.request.object.spec.tls.#.hosts").Array() {
		for _, tlsHost := range host.Array() {
			tlsHosts = append(tlsHosts, tlsHost.String())
		}
	}
	for _, host := range gjson.Get(string(payload), "request.request.object.spec.rules.#.host").Array() {
		rulesHosts = append(rulesHosts, host.String())
	}
	settings := gjson.Get(string(payload), "settings")
	if settingsRequireTLS([]byte(settings.String())) {
		if !slicesAreEqualOrderInsensitive(tlsHosts, rulesHosts) {
			return chimera.RejectRequest(chimera.Message("not all hosts have TLS configuration"), chimera.NoCode)
		}
	}
	ingressPorts := ingressPorts(payload)
	settingsDenyPorts := settingsDenyPorts([]byte(settings.String()))
	if len(settingsDenyPorts) > 0 {
		for _, ingressPort := range ingressPorts {
			if _, ok := settingsDenyPorts[ingressPort]; ok {
				return chimera.RejectRequest(chimera.Message(fmt.Sprintf("port %d is in the list of denied ports", ingressPort)), chimera.NoCode)
			}
		}
	}
	settingsAllowPorts := settingsAllowPorts([]byte(settings.String()))
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
	return gjson.Get(string(payload), "requireTLS").Bool()
}

func settingsAllowPorts(payload []byte) map[uint16]struct{} {
	allowPorts := map[uint16]struct{}{}
	for _, port := range gjson.Get(string(payload), "allowPorts").Array() {
		port, err := strconv.ParseUint(port.String(), 10, 16)
		if err != nil {
			continue
		}
		allowPorts[uint16(port)] = struct{}{}
	}
	return allowPorts
}

func settingsDenyPorts(payload []byte) map[uint16]struct{} {
	denyPorts := map[uint16]struct{}{}
	for _, port := range gjson.Get(string(payload), "denyPorts").Array() {
		port, err := strconv.ParseUint(port.String(), 10, 16)
		if err != nil {
			continue
		}
		denyPorts[uint16(port)] = struct{}{}
	}
	return denyPorts
}

func main() {
	wapc.RegisterFunctions(wapc.Functions{
		"validate": validate,
	})
}
