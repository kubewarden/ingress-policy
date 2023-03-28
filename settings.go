package main

import (
	mapset "github.com/deckarep/golang-set/v2"
	kubewarden "github.com/kubewarden/policy-sdk-go"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
	easyjson "github.com/mailru/easyjson"
)

type Settings struct {
	RequireTls bool       `json:"requireTLS"`
	AllowPorts mapset.Set[uint64] `json:"allowPorts"`
	DenyPorts  mapset.Set[uint64] `json:"denyPorts"`
}

func NewSettingsFromRaw(rawSettings *RawSettings) Settings {
	allowPorts := mapset.NewThreadUnsafeSet[uint64](rawSettings.AllowPorts...)
	denyPorts := mapset.NewThreadUnsafeSet[uint64](rawSettings.DenyPorts...)

	return Settings{
		RequireTls: rawSettings.RequireTls,
		AllowPorts: allowPorts,
		DenyPorts:  denyPorts,
	}
}

func NewSettingsFromValidationReq(validationReq *kubewarden_protocol.ValidationRequest) (Settings, error) {
	rawSettings := RawSettings{}
	err := easyjson.Unmarshal(validationReq.Settings, &rawSettings)
	if err != nil {
		return Settings{}, err
	}

	return NewSettingsFromRaw(&rawSettings), nil
}

// The AllowPorts and DenyPorts should not have any
// element in common
func (s *Settings) Valid() bool {
	common := s.AllowPorts.Intersect(s.DenyPorts)
	return common.Cardinality() == 0
}

func validateSettings(payload []byte) ([]byte, error) {
	rawSettings := RawSettings{}
	err := easyjson.Unmarshal(payload, &rawSettings)
	if err != nil {
		return []byte{}, err
	}

	settings := NewSettingsFromRaw(&rawSettings)
	if settings.Valid() {
		return kubewarden.AcceptSettings()
	}
	return kubewarden.RejectSettings(kubewarden.Message("No port can be allowed and denied at the same time"))
}
