package main

import (
	"encoding/json"
	"testing"

	"github.com/deckarep/golang-set"
	kubewarden_testing "github.com/kubewarden/policy-sdk-go/testing"
)

func TestCheckAllowedPortsEmptyAllowedPorts(t *testing.T) {
	settings := Settings{
		AllowPorts: mapset.NewThreadUnsafeSetFromSlice([]interface{}{}),
	}

	ports := mapset.NewThreadUnsafeSetFromSlice([]interface{}{80})

	if err := checkAllowedPorts(ports, &settings); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}
}

func TestCheckAllowedPortsOnlyAllowedPortsAreUsed(t *testing.T) {
	settings := Settings{
		AllowPorts: mapset.NewThreadUnsafeSetFromSlice([]interface{}{80, 443}),
	}

	ports := mapset.NewThreadUnsafeSetFromSlice([]interface{}{80})

	if err := checkAllowedPorts(ports, &settings); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}
}

func TestCheckAllowedPortsSomeNotAllowedPortsAreUsed(t *testing.T) {
	settings := Settings{
		AllowPorts: mapset.NewThreadUnsafeSetFromSlice([]interface{}{443}),
	}

	ports := mapset.NewThreadUnsafeSetFromSlice([]interface{}{443, 80})

	if err := checkAllowedPorts(ports, &settings); err == nil {
		t.Errorf("No error returned")
	}
}

func TestCheckDeniedPortsEmptyAllowedPorts(t *testing.T) {
	settings := Settings{
		DenyPorts: mapset.NewThreadUnsafeSetFromSlice([]interface{}{}),
	}

	ports := mapset.NewThreadUnsafeSetFromSlice([]interface{}{80})

	if err := checkDeniedPorts(ports, &settings); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}
}

func TestCheckDeniedPortsNoDeniedPortAreUsed(t *testing.T) {
	settings := Settings{
		DenyPorts: mapset.NewThreadUnsafeSetFromSlice([]interface{}{80}),
	}

	ports := mapset.NewThreadUnsafeSetFromSlice([]interface{}{443})

	if err := checkDeniedPorts(ports, &settings); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}
}

func TestCheckDeniedPortsSomeDeniedPortsAreUsed(t *testing.T) {
	settings := Settings{
		DenyPorts: mapset.NewThreadUnsafeSetFromSlice([]interface{}{80}),
	}

	ports := mapset.NewThreadUnsafeSetFromSlice([]interface{}{443, 80})

	if err := checkDeniedPorts(ports, &settings); err == nil {
		t.Errorf("No error returned")
	}
}

func TestParsePorts(t *testing.T) {
	payload, err := kubewarden_testing.BuildValidationRequest(
		"test_data/ingress-wildcard.json",
		&Settings{})
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	actual := parsePorts(payload)
	expected := mapset.NewThreadUnsafeSetFromSlice(
		[]interface{}{uint64(80), uint64(3000)})
	if !actual.Equal(expected) {
		t.Errorf("Got %+v instead of %+v", actual, expected)
	}
}

func TestCheckTlsSettingsNotEnforced(t *testing.T) {
	settings := Settings{
		RequireTls: false,
	}

	payload, err := kubewarden_testing.BuildValidationRequest(
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

	payload, err := kubewarden_testing.BuildValidationRequest(
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

	payload, err := kubewarden_testing.BuildValidationRequest(
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

	payload, err := kubewarden_testing.BuildValidationRequest(
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

	var response kubewarden_testing.ValidationResponse
	if err := json.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != false {
		t.Error("Unexpected approval")
	}

	expected_message := "Not a valid JSON document"
	if response.Message != expected_message {
		t.Errorf("Got '%s' instead of '%s'", response.Message, expected_message)
	}
}

func TestValidationTlsRejection(t *testing.T) {
	settings := Settings{
		RequireTls: true,
	}

	payload, err := kubewarden_testing.BuildValidationRequest(
		"test_data/multiple-backends-with-partial-tls-termination.json",
		&settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_testing.ValidationResponse
	if err := json.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != false {
		t.Error("Unexpected approval")
	}

	expected_message := "Not all hosts have TLS enabled"
	if response.Message != expected_message {
		t.Errorf("Got '%s' instead of '%s'", response.Message, expected_message)
	}
}

func TestValidationAllowedPortsRejection(t *testing.T) {
	settings := Settings{
		RequireTls: false,
		AllowPorts: mapset.NewThreadUnsafeSetFromSlice([]interface{}{uint64(5000)}),
		DenyPorts:  mapset.NewThreadUnsafeSetFromSlice([]interface{}{}),
	}

	payload, err := kubewarden_testing.BuildValidationRequest(
		"test_data/multiple-backends-with-partial-tls-termination.json",
		&settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_testing.ValidationResponse
	if err := json.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != false {
		t.Error("Unexpected approval")
	}

	expected_message := "These ports are not on the allowed list: Set{80}"
	if response.Message != expected_message {
		t.Errorf("Got '%s' instead of '%s'", response.Message, expected_message)
	}
}

func TestValidationDeniedPortsRejection(t *testing.T) {
	settings := Settings{
		RequireTls: false,
		AllowPorts: mapset.NewThreadUnsafeSetFromSlice([]interface{}{}),
		DenyPorts:  mapset.NewThreadUnsafeSetFromSlice([]interface{}{uint64(80)}),
	}

	payload, err := kubewarden_testing.BuildValidationRequest(
		"test_data/multiple-backends-with-partial-tls-termination.json",
		&settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_testing.ValidationResponse
	if err := json.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != false {
		t.Error("Unexpected approval")
	}

	expected_message := "These ports are explicitly denied: Set{80}"
	if response.Message != expected_message {
		t.Errorf("Got '%s' instead of '%s'", response.Message, expected_message)
	}
}

func TestValidationAccept(t *testing.T) {
	settings := Settings{
		RequireTls: true,
		AllowPorts: mapset.NewThreadUnsafeSetFromSlice([]interface{}{}),
		DenyPorts:  mapset.NewThreadUnsafeSetFromSlice([]interface{}{uint64(8080)}),
	}

	payload, err := kubewarden_testing.BuildValidationRequest(
		"test_data/single-backend-with-tls-termination.json",
		&settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_testing.ValidationResponse
	if err := json.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != true {
		t.Error("Unexpected rejection")
	}
}
