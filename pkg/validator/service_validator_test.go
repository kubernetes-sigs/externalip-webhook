package validator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNewServiceValidatorInvalidInput(t *testing.T) {
	newServiceValidator, err := NewServiceValidator([]string{"12.1.1.a"})
	assert.Errorf(t, err, "unable to parse input cidr 12.1.1.a")
	assert.Nil(t, newServiceValidator)
}

func TestNewServiceValidatorHappyCase(t *testing.T) {
	newServiceValidator, err := NewServiceValidator([]string{"10.0.0.0/8"})
	assert.Nil(t, err)
	assert.Len(t, newServiceValidator.allowedExternalIPNets, 1)
}

func TestValidateExternalIPForSingleAllowedIP(t *testing.T) {
	newServiceValidator, _ := NewServiceValidator([]string{"10.0.0.0/8"})
	actualOutput := newServiceValidator.validateExternalIPs([]string{"10.0.0.5"})
	assert.True(t, actualOutput.Allowed)
}

func TestValidateExternalIPForMultipleAllowedIPs(t *testing.T) {
	newServiceValidator, _ := NewServiceValidator([]string{"10.0.0.0/8", "11.0.0.0/8"})
	actualOutput := newServiceValidator.validateExternalIPs([]string{"11.0.0.5"})
	assert.True(t, actualOutput.Allowed)
}

func TestValidateExternalIPForSingleInvalidInput(t *testing.T) {
	newServiceValidator, _ := NewServiceValidator([]string{"10.0.0.0/8"})
	actualOutput := newServiceValidator.validateExternalIPs([]string{"1.2.e.4"})
	assert.False(t, actualOutput.Allowed)
	assert.Equal(t, actualOutput.Result.Reason, v1.StatusReason("spec.externalIPs: Invalid value: "+
		"\"1.2.e.4\": externalIP specified is not valid"))
}

func TestValidateExternalIPForMultipleInvalidInput(t *testing.T) {
	newServiceValidator, _ := NewServiceValidator([]string{"10.0.0.0/8"})
	actualOutput := newServiceValidator.validateExternalIPs([]string{"10.0.0.5", "11.0.0.1"})
	assert.False(t, actualOutput.Allowed)
	assert.Equal(t, actualOutput.Result.Reason, v1.StatusReason("spec.externalIPs: Invalid value: "+
		"\"11.0.0.1\": externalIP specified is not allowed to use"))
}
