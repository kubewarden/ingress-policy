package main

import (
	"encoding/json"

	mapset "github.com/deckarep/golang-set/v2"
	kubewarden "github.com/kubewarden/policy-sdk-go"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
)

type Settings struct {
	RequireTls bool               `json:"requireTLS"`
	AllowPorts mapset.Set[uint64] `json:"allowPorts"`
	DenyPorts  mapset.Set[uint64] `json:"denyPorts"`
}

func NewSettingsFromValidationReq(validationReq *kubewarden_protocol.ValidationRequest) (Settings, error) {
	settings := Settings{}
	err := json.Unmarshal(validationReq.Settings, &settings)
	if err != nil {
		return Settings{}, err
	}

	return settings, nil
}

// The AllowPorts and DenyPorts should not have any
// element in common
func (s *Settings) Valid() bool {
	common := s.AllowPorts.Intersect(s.DenyPorts)
	return common.Cardinality() == 0
}

func (s *Settings) UnmarshalJSON(data []byte) error {
	// This is needed becaus golang-set v2.3.0 has a bug that prevents
	// the correct unmarshalling of ThreadUnsafeSet types.
	rawSettings := struct {
		RequireTls bool     `json:"requireTLS"`
		AllowPorts []uint64 `json:"allowPorts"`
		DenyPorts  []uint64 `json:"denyPorts"`
	}{}

	err := json.Unmarshal(data, &rawSettings)
	if err != nil {
		return err
	}

	s.RequireTls = rawSettings.RequireTls
	s.AllowPorts = mapset.NewThreadUnsafeSet[uint64](rawSettings.AllowPorts...)
	s.DenyPorts = mapset.NewThreadUnsafeSet[uint64](rawSettings.DenyPorts...)

	return nil
}

func validateSettings(payload []byte) ([]byte, error) {
	settings := Settings{}
	err := json.Unmarshal(payload, &settings)
	if err != nil {
		return []byte{}, err
	}

	if settings.Valid() {
		return kubewarden.AcceptSettings()
	}

	return kubewarden.RejectSettings(kubewarden.Message("No port can be allowed and denied at the same time"))
}
