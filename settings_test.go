package main

import (
	"testing"
)

func TestParsingSettingsWithAllValuesProvidedFromValidationReq(t *testing.T) {
	request := `
	{
		"request": "doesn't matter here",
		"settings": {
			"requireTLS": true,
			"allowPorts": [ 443 ],
			"denyPorts": [ 80, 8080 ]
		}
	}
	`
	rawRequest := []byte(request)

	settings, err := NewSettingsFromValidationReq(rawRequest)
	if err != nil {
		t.Errorf("Unexpected error %+v", err)
	}

	if settings.RequireTls != true {
		t.Errorf("Wrong value for RequireTls")
	}

	if !settings.AllowPorts.Contains(uint64(443)) {
		t.Errorf("Missing value from AllowPorts")
	}

	expectedDenyPorts := []uint64{80, 8080}
	for _, port := range expectedDenyPorts {
		if !settings.DenyPorts.Contains(port) {
			t.Errorf("Missing port %v from DenyPorts", port)
		}
	}
}

func TestParsingSettingsWithSomeValuesProvided(t *testing.T) {
	request := `
	{
		"request": "doesn't matter here",
		"settings": {
			"allowPorts": [ 443 ]
		}
	}
	`
	rawRequest := []byte(request)

	settings, err := NewSettingsFromValidationReq(rawRequest)
	if err != nil {
		t.Errorf("Unexpected error %+v", err)
	}

	if settings.RequireTls != false {
		t.Errorf("Wrong value for RequireTls")
	}

	if !settings.AllowPorts.Contains(uint64(443)) {
		t.Errorf("Missing value from AllowPorts")
	}

	if settings.DenyPorts.Cardinality() != 0 {
		t.Errorf("Expecpted DenyPorts to be empty")
	}
}

func TestParsingSettingsFromValidateSettingsPayload(t *testing.T) {
	request := `
	{
		"requireTLS": true,
		"allowPorts": [ 443 ],
		"denyPorts": [ 80, 8080 ]
	}
	`
	rawRequest := []byte(request)

	settings, err := NewSettingsFromValidateSettingsPayload(rawRequest)
	if err != nil {
		t.Errorf("Unexpected error %+v", err)
	}

	if settings.RequireTls != true {
		t.Errorf("Wrong value for RequireTls")
	}

	if !settings.AllowPorts.Contains(uint64(443)) {
		t.Errorf("Missing value from AllowPorts")
	}

	expectedDenyPorts := []uint64{80, 8080}
	for _, port := range expectedDenyPorts {
		if !settings.DenyPorts.Contains(port) {
			t.Errorf("Missing port %v from DenyPorts", port)
		}
	}
}

func TestSettingsAreValid(t *testing.T) {
	request := `
	{
		"requireTLS": true,
		"allowPorts": [ 443 ],
		"denyPorts": [ 80, 8080 ]
	}
	`
	rawRequest := []byte(request)

	settings, err := NewSettingsFromValidateSettingsPayload(rawRequest)
	if err != nil {
		t.Errorf("Unexpected error %+v", err)
	}

	if settings.Valid() != true {
		t.Errorf("Settings are not reported as Valid")
	}
}

func TestSettingsAreNotValid(t *testing.T) {
	request := `
	{
		"requireTLS": true,
		"allowPorts": [ 80 ],
		"denyPorts": [ 80, 8080 ]
	}
	`
	rawRequest := []byte(request)

	settings, err := NewSettingsFromValidateSettingsPayload(rawRequest)
	if err != nil {
		t.Errorf("Unexpected error %+v", err)
	}

	if settings.Valid() != false {
		t.Errorf("Settings are reported as Valid")
	}
}
