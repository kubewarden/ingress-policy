package main

import (
	"github.com/deckarep/golang-set"
	"github.com/kubewarden/gjson"
	kubewarden "github.com/kubewarden/policy-sdk-go"

	"fmt"
)

type Settings struct {
	RequireTls bool       `json:"requireTLS"`
	AllowPorts mapset.Set `json:"allowPorts"`
	DenyPorts  mapset.Set `json:"denyPorts"`
}

// Builds a new Settings instance starting from a validation
// request payload:
// {
//    "request": ...,
//    "settings": {
//       requireTLS: ...
//    }
// }
func NewSettingsFromValidationReq(payload []byte) (Settings, error) {
	// Note well: we don't validate the input JSON now, this has
	// already done inside of the `validate` function

	return newSettings(
		payload,
		"settings.requireTLS",
		"settings.allowPorts",
		"settings.denyPorts")
}

// Builds a new Settings instance starting from a Settings
// payload:
// {
//    "requireTLS": ...
// }
func NewSettingsFromValidateSettingsPayload(payload []byte) (Settings, error) {
	if !gjson.ValidBytes(payload) {
		return Settings{}, fmt.Errorf("invalid JSON payload")
	}

	return newSettings(
		payload,
		"requireTLS",
		"allowPorts",
		"denyPorts")
}

func newSettings(payload []byte, paths ...string) (Settings, error) {
	if len(paths) != 3 {
		return Settings{}, fmt.Errorf("wrong number of json paths")
	}

	data := gjson.GetManyBytes(payload, paths...)

	requireTLS := false
	if data[0].Exists() {
		requireTLS = data[0].Bool()
	}

	allowPorts := mapset.NewThreadUnsafeSet()
	data[1].ForEach(func(_, entry gjson.Result) bool {
		allowPorts.Add(entry.Uint())
		return true
	})

	denyPorts := mapset.NewThreadUnsafeSet()
	data[2].ForEach(func(_, entry gjson.Result) bool {
		denyPorts.Add(entry.Uint())
		return true
	})

	return Settings{
		RequireTls: requireTLS,
		AllowPorts: allowPorts,
		DenyPorts:  denyPorts,
	}, nil

}

// The AllowPorts and DenyPorts should not have any
// element in common
func (s *Settings) Valid() bool {
	common := s.AllowPorts.Intersect(s.DenyPorts)
	return common.Cardinality() == 0
}

func validateSettings(payload []byte) ([]byte, error) {
	settings, err := NewSettingsFromValidateSettingsPayload(payload)
	if err != nil {
		return []byte{}, err
	}

	if settings.Valid() {
		return kubewarden.AcceptSettings()
	}
	return kubewarden.RejectSettings(kubewarden.Message("No port can be allowed and denied at the same time"))
}
