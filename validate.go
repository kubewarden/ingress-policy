package main

import (
	"encoding/json"
	"fmt"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/kubewarden/gjson"
	kubewarden "github.com/kubewarden/policy-sdk-go"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
)

func validate(payload []byte) ([]byte, error) {
	validationRequest := kubewarden_protocol.ValidationRequest{}
	err := json.Unmarshal(payload, &validationRequest)
	if err != nil {
		return kubewarden.RejectRequest(
			kubewarden.Message(err.Error()),
			kubewarden.Code(400))
	}

	// Create a Settings instance from the ValidationRequest object
	settings, err := NewSettingsFromValidationReq(&validationRequest)
	if err != nil {
		return kubewarden.RejectRequest(
			kubewarden.Message(err.Error()),
			kubewarden.Code(400))
	}

	if !checkTlsSettings(payload, &settings) {
		return kubewarden.RejectRequest(
			kubewarden.Message("Not all hosts have TLS enabled"),
			kubewarden.NoCode)
	}

	ports := parsePorts(payload)
	if err := checkAllowedPorts(ports, &settings); err != nil {
		return kubewarden.RejectRequest(
			kubewarden.Message(err.Error()),
			kubewarden.NoCode)
	}
	if err := checkDeniedPorts(ports, &settings); err != nil {
		return kubewarden.RejectRequest(
			kubewarden.Message(err.Error()),
			kubewarden.NoCode)
	}

	return kubewarden.AcceptRequest()
}

func checkTlsSettings(payload []byte, settings *Settings) bool {
	if !settings.RequireTls {
		return true
	}

	tlsHost := mapset.NewThreadUnsafeSet[string]()
	rulesHosts := mapset.NewThreadUnsafeSet[string]()

	// still using gjson because it makes the code more compact
	data := gjson.GetManyBytes(
		payload,
		"request.object.spec.tls.#.hosts|@flatten",
		"request.object.spec.rules.#.host|@flatten")

	data[0].ForEach(func(_, entry gjson.Result) bool {
		tlsHost.Add(entry.String())
		return true
	})

	data[1].ForEach(func(_, entry gjson.Result) bool {
		rulesHosts.Add(entry.String())
		return true
	})

	return tlsHost.Equal(rulesHosts)
}

func parsePorts(payload []byte) mapset.Set[uint64] {
	ports := mapset.NewThreadUnsafeSet[uint64]()

	// still using gjson because it makes the code more compact
	data := gjson.GetBytes(
		payload,
		"request.object.spec.rules.#.http.paths.#.backend.service.port.number|@flatten")
	data.ForEach(func(_, entry gjson.Result) bool {
		ports.Add(entry.Uint())
		return true
	})

	return ports
}

func checkAllowedPorts(ports mapset.Set[uint64], settings *Settings) error {
	if settings.AllowPorts.Cardinality() == 0 {
		return nil
	}

	notAllowed := ports.Difference(settings.AllowPorts)
	if notAllowed.Cardinality() == 0 {
		return nil
	}

	return fmt.Errorf("these ports are not on the allowed list: %v", notAllowed)
}

func checkDeniedPorts(ports mapset.Set[uint64], settings *Settings) error {
	if settings.DenyPorts.Cardinality() == 0 {
		return nil
	}

	denied := ports.Intersect(settings.DenyPorts)
	if denied.Cardinality() == 0 {
		return nil
	}

	return fmt.Errorf("these ports are explicitly denied: %v", denied)
}
