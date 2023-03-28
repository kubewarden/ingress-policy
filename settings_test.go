package main

import (
	"testing"

	networkingv1 "github.com/kubewarden/k8s-objects/api/networking/v1"
	metav1 "github.com/kubewarden/k8s-objects/apimachinery/pkg/apis/meta/v1"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
	kubewarden_testing "github.com/kubewarden/policy-sdk-go/testing"
	"github.com/mailru/easyjson"
)

func TestParsingSettingsWithAllValuesProvidedFromValidationReq(t *testing.T) {
	ingress := networkingv1.Ingress{
		Metadata: &metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
	}

	rawSettings := RawSettings{
		RequireTls: true,
		AllowPorts: []uint64{443},
		DenyPorts:  []uint64{80, 8080},
	}

	validationReqRaw, err := kubewarden_testing.BuildValidationRequest(ingress, rawSettings)
	if err != nil {
		t.Errorf("Unexpected error %+v", err)
	}
	validationReq := kubewarden_protocol.ValidationRequest{}
	err = easyjson.Unmarshal(validationReqRaw, &validationReq)
	if err != nil {
		t.Errorf("Unexpected error %+v", err)
	}

	settings, err := NewSettingsFromValidationReq(&validationReq)
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
	ingress := networkingv1.Ingress{
		Metadata: &metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
	}

	rawSettings := RawSettings{
		RequireTls: false,
		AllowPorts: []uint64{443},
		DenyPorts:  []uint64{},
	}

	validationReqRaw, err := kubewarden_testing.BuildValidationRequest(ingress, rawSettings)
	if err != nil {
		t.Errorf("Unexpected error %+v", err)
	}
	validationReq := kubewarden_protocol.ValidationRequest{}
	err = easyjson.Unmarshal(validationReqRaw, &validationReq)
	if err != nil {
		t.Errorf("Unexpected error %+v", err)
	}

	settings, err := NewSettingsFromValidationReq(&validationReq)
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
	rawRequest := RawSettings{}
	err := easyjson.Unmarshal([]byte(request), &rawRequest)
	if err != nil {
		t.Errorf("Unexpected error %+v", err)
	}

	settings := NewSettingsFromRaw(&rawRequest)
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
	rawRequest := RawSettings{}
	err := easyjson.Unmarshal([]byte(request), &rawRequest)
	if err != nil {
		t.Errorf("Unexpected error %+v", err)
	}

	settings := NewSettingsFromRaw(&rawRequest)
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
	rawRequest := RawSettings{}
	err := easyjson.Unmarshal([]byte(request), &rawRequest)
	if err != nil {
		t.Errorf("Unexpected error %+v", err)
	}

	settings := NewSettingsFromRaw(&rawRequest)
	if err != nil {
		t.Errorf("Unexpected error %+v", err)
	}

	if settings.Valid() != false {
		t.Errorf("Settings are reported as Valid")
	}
}
