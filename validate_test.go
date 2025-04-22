package main

import (
	"encoding/json"
	"testing"

	mapset "github.com/deckarep/golang-set/v2"

	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
	kubewarden_testing "github.com/kubewarden/policy-sdk-go/testing"
)

func TestCheckAllowedPortsEmptyAllowedPorts(t *testing.T) {
	settings := Settings{
		AllowPorts: mapset.NewThreadUnsafeSet[uint64](),
	}

	ports := mapset.NewThreadUnsafeSet[uint64](80)

	if err := checkAllowedPorts(ports, &settings); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}
}

func TestCheckAllowedPortsOnlyAllowedPortsAreUsed(t *testing.T) {
	settings := Settings{
		AllowPorts: mapset.NewThreadUnsafeSet[uint64](80, 443),
	}

	ports := mapset.NewThreadUnsafeSet[uint64](80)

	if err := checkAllowedPorts(ports, &settings); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}
}

func TestCheckAllowedPortsSomeNotAllowedPortsAreUsed(t *testing.T) {
	settings := Settings{
		AllowPorts: mapset.NewThreadUnsafeSet[uint64](443),
	}

	ports := mapset.NewThreadUnsafeSet[uint64](443, 80)

	if err := checkAllowedPorts(ports, &settings); err == nil {
		t.Errorf("No error returned")
	}
}

func TestCheckDeniedPortsEmptyAllowedPorts(t *testing.T) {
	settings := Settings{
		DenyPorts: mapset.NewThreadUnsafeSet[uint64](),
	}

	ports := mapset.NewThreadUnsafeSet[uint64](80)

	if err := checkDeniedPorts(ports, &settings); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}
}

func TestCheckDeniedPortsNoDeniedPortAreUsed(t *testing.T) {
	settings := Settings{
		DenyPorts: mapset.NewThreadUnsafeSet[uint64](80),
	}

	ports := mapset.NewThreadUnsafeSet[uint64](443)

	if err := checkDeniedPorts(ports, &settings); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}
}

func TestCheckDeniedPortsSomeDeniedPortsAreUsed(t *testing.T) {
	settings := Settings{
		DenyPorts: mapset.NewThreadUnsafeSet[uint64](80),
	}

	ports := mapset.NewThreadUnsafeSet[uint64](443, 80)

	if err := checkDeniedPorts(ports, &settings); err == nil {
		t.Errorf("No error returned")
	}
}

func TestParsePorts(t *testing.T) {
	payload, err := kubewarden_testing.BuildValidationRequestFromFixture(
		"test_data/ingress-wildcard.json",
		&Settings{})
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	actual := parsePorts(payload)
	expected := mapset.NewThreadUnsafeSet[uint64](80, 3000)
	if !actual.Equal(expected) {
		t.Errorf("Got %+v instead of %+v", actual, expected)
	}
}

func TestCheckTlsSettingsNotEnforced(t *testing.T) {
	settings := Settings{
		RequireTls: false,
	}

	payload, err := kubewarden_testing.BuildValidationRequestFromFixture(
		"test_data/ingress-wildcard.json",
		&settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if checkTlsSettings(payload, &settings) != true {
		t.Errorf("Unexpected rejection")
	}
}

func TestCheckTlsSettingsEnforcedAndTlsNotConfigured(t *testing.T) {
	settings := Settings{
		RequireTls: true,
	}

	payload, err := kubewarden_testing.BuildValidationRequestFromFixture(
		"test_data/ingress-wildcard.json",
		&settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if checkTlsSettings(payload, &settings) != false {
		t.Errorf("Unexpected approval")
	}
}

func TestCheckTlsSettingsEnforcedAndTlsConfigured(t *testing.T) {
	settings := Settings{
		RequireTls: true,
	}

	payload, err := kubewarden_testing.BuildValidationRequestFromFixture(
		"test_data/single-backend-with-tls-termination.json",
		&settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if checkTlsSettings(payload, &settings) != true {
		t.Errorf("Unexpected rejection")
	}
}

func TestCheckTlsSettingsEnforcedAndPartialTlsConfiguration(t *testing.T) {
	settings := Settings{
		RequireTls: true,
	}

	payload, err := kubewarden_testing.BuildValidationRequestFromFixture(
		"test_data/multiple-backends-with-partial-tls-termination.json",
		&settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if checkTlsSettings(payload, &settings) != false {
		t.Errorf("Unexpected approval")
	}
}

func TestValidationRejectionDueToInvalidJSON(t *testing.T) {
	payload := []byte(`boom baby!`)

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_protocol.ValidationResponse
	if err := json.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != false {
		t.Error("Unexpected approval")
	}

	expectedMessage := "invalid character 'b' looking for beginning of value"
	if *response.Message != expectedMessage {
		t.Errorf("Got '%s' instead of '%s'", *response.Message, expectedMessage)
	}
}

func TestValidationTlsRejection(t *testing.T) {
	settings := Settings{
		RequireTls: true,
	}

	payload, err := kubewarden_testing.BuildValidationRequestFromFixture(
		"test_data/multiple-backends-with-partial-tls-termination.json",
		&settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_protocol.ValidationResponse
	if err := json.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != false {
		t.Error("Unexpected approval")
	}

	expectedMessage := "Not all hosts have TLS enabled"
	if *response.Message != expectedMessage {
		t.Errorf("Got '%s' instead of '%s'", *response.Message, expectedMessage)
	}
}

func TestValidationAllowedPortsRejection(t *testing.T) {
	settings := Settings{
		RequireTls: false,
		AllowPorts: mapset.NewThreadUnsafeSet[uint64](5000),
		DenyPorts:  mapset.NewThreadUnsafeSet[uint64](),
	}

	payload, err := kubewarden_testing.BuildValidationRequestFromFixture(
		"test_data/multiple-backends-with-partial-tls-termination.json",
		&settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_protocol.ValidationResponse
	if err := json.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != false {
		t.Error("Unexpected approval")
	}

	expectedMessage := "these ports are not on the allowed list: Set{80}"
	if *response.Message != expectedMessage {
		t.Errorf("Got '%s' instead of '%s'", *response.Message, expectedMessage)
	}
}

func TestValidationDeniedPortsRejection(t *testing.T) {
	settings := Settings{
		RequireTls: false,
		AllowPorts: mapset.NewThreadUnsafeSet[uint64](),
		DenyPorts:  mapset.NewThreadUnsafeSet[uint64](80),
	}

	payload, err := kubewarden_testing.BuildValidationRequestFromFixture(
		"test_data/multiple-backends-with-partial-tls-termination.json",
		&settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_protocol.ValidationResponse
	if err := json.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != false {
		t.Error("Unexpected approval")
	}

	expectedMessage := "these ports are explicitly denied: Set{80}"
	if *response.Message != expectedMessage {
		t.Errorf("Got '%s' instead of '%s'", *response.Message, expectedMessage)
	}
}

func TestValidationAccept(t *testing.T) {
	settings := Settings{
		RequireTls: true,
		AllowPorts: mapset.NewThreadUnsafeSet[uint64](),
		DenyPorts:  mapset.NewThreadUnsafeSet[uint64](8080),
	}

	payload, err := kubewarden_testing.BuildValidationRequestFromFixture(
		"test_data/single-backend-with-tls-termination.json",
		&settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_protocol.ValidationResponse
	if err := json.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != true {
		t.Error("Unexpected rejection")
	}
}
