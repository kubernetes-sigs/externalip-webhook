package validator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	authenticationv1 "k8s.io/api/authentication/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNewServiceValidatorInvalidInput(t *testing.T) {
	newServiceValidator, err := NewServiceValidator([]string{"12.1.1.a"}, []string{}, []string{})
	assert.Errorf(t, err, "unable to parse input cidr 12.1.1.a")
	assert.Nil(t, newServiceValidator)
}

func TestNewServiceValidatorHappyCase(t *testing.T) {
	newServiceValidator, err := NewServiceValidator([]string{"10.0.0.0/8"}, []string{}, []string{})
	assert.Nil(t, err)
	assert.Len(t, newServiceValidator.allowedExternalIPNets, 1)
}

func TestValidateExternalIPForSingleAllowedIP(t *testing.T) {
	newServiceValidator, _ := NewServiceValidator([]string{"10.0.0.0/8"}, []string{}, []string{})
	actualOutput := newServiceValidator.validateExternalIPs([]string{"10.0.0.5"})
	assert.True(t, actualOutput.Allowed)
}

func TestValidateExternalIPForMultipleAllowedIPs(t *testing.T) {
	newServiceValidator, _ := NewServiceValidator([]string{"10.0.0.0/8", "11.0.0.0/8"}, []string{}, []string{})
	actualOutput := newServiceValidator.validateExternalIPs([]string{"11.0.0.5"})
	assert.True(t, actualOutput.Allowed)
}

func TestValidateExternalIPForSingleInvalidInput(t *testing.T) {
	newServiceValidator, _ := NewServiceValidator([]string{"10.0.0.0/8"}, []string{}, []string{})
	actualOutput := newServiceValidator.validateExternalIPs([]string{"1.2.e.4"})
	assert.False(t, actualOutput.Allowed)
	assert.Equal(t, actualOutput.Result.Reason, v1.StatusReason("spec.externalIPs: Invalid value: "+
		"\"1.2.e.4\": externalIP specified is not valid"))
}

func TestValidateExternalIPForMultipleInvalidInput(t *testing.T) {
	newServiceValidator, _ := NewServiceValidator([]string{"10.0.0.0/8"}, []string{}, []string{})
	actualOutput := newServiceValidator.validateExternalIPs([]string{"10.0.0.5", "11.0.0.1"})
	assert.False(t, actualOutput.Allowed)
	assert.Equal(t, actualOutput.Result.Reason, v1.StatusReason("spec.externalIPs: Invalid value: "+
		"\"11.0.0.1\": externalIP specified is not allowed to use"))
}

func TestIsValidUserEmptyAllowedBoth(t *testing.T) {
	newServiceValidator, _ := NewServiceValidator([]string{"10.0.0.0/8"}, []string{}, []string{})
	actualOutput := newServiceValidator.isValidUser(authenticationv1.UserInfo{Username: "user1", Groups: []string{"group1"}})
	assert.True(t, actualOutput)
}

func TestIsValidUserEmptyAllowedUserNoMatch(t *testing.T) {
	newServiceValidator, _ := NewServiceValidator([]string{"10.0.0.0/8"}, []string{}, []string{"group2"})
	actualOutput := newServiceValidator.isValidUser(authenticationv1.UserInfo{Username: "user1", Groups: []string{"group1"}})
	assert.False(t, actualOutput)
}

func TestIsValidUserEmptyAllowedUserGroupMatch(t *testing.T) {
	newServiceValidator, _ := NewServiceValidator([]string{"10.0.0.0/8"}, []string{}, []string{"group1"})
	actualOutput := newServiceValidator.isValidUser(authenticationv1.UserInfo{Username: "user1", Groups: []string{"group1"}})
	assert.True(t, actualOutput)
}

func TestIsValidUserEmptyAllowedGroupNoMatch(t *testing.T) {
	newServiceValidator, _ := NewServiceValidator([]string{"10.0.0.0/8"}, []string{"user2"}, []string{})
	actualOutput := newServiceValidator.isValidUser(authenticationv1.UserInfo{Username: "user1", Groups: []string{"group1"}})
	assert.False(t, actualOutput)
}

func TestIsValidUserEmptyAllowedGroupUserMatch(t *testing.T) {
	newServiceValidator, _ := NewServiceValidator([]string{"10.0.0.0/8"}, []string{"user1"}, []string{})
	actualOutput := newServiceValidator.isValidUser(authenticationv1.UserInfo{Username: "user1", Groups: []string{"group1"}})
	assert.True(t, actualOutput)
}

func TestIsValidUserOnlyUsernameMatch(t *testing.T) {
	newServiceValidator, _ := NewServiceValidator([]string{"10.0.0.0/8"}, []string{"user2", "user1"}, []string{"group2"})
	actualOutput := newServiceValidator.isValidUser(authenticationv1.UserInfo{Username: "user1", Groups: []string{"group1"}})
	assert.True(t, actualOutput)
}

func TestIsValidUserOnlyGroupMatch(t *testing.T) {
	newServiceValidator, _ := NewServiceValidator([]string{"10.0.0.0/8"}, []string{"user2"}, []string{"group2", "group1"})
	actualOutput := newServiceValidator.isValidUser(authenticationv1.UserInfo{Username: "user1", Groups: []string{"group1"}})
	assert.True(t, actualOutput)
}

func TestIsValidUserNoMatch(t *testing.T) {
	newServiceValidator, _ := NewServiceValidator([]string{"10.0.0.0/8"}, []string{"user2"}, []string{"group2"})
	actualOutput := newServiceValidator.isValidUser(authenticationv1.UserInfo{Username: "user1", Groups: []string{"group1"}})
	assert.False(t, actualOutput)
}
