package validator

import (
	"context"
	"testing"
	"time"

	"github.com/ghodss/yaml"
	"github.com/stretchr/testify/assert"
	admissionv1beta1 "k8s.io/api/admission/v1beta1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
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

var (
	serviceWithoutExternalIP = `
apiVersion: v1
kind: Service
metadata:
  name: test
spec:
  ports:
    - protocol: TCP
      port: 80
`

	serviceWithAllowedExternalIP = `
apiVersion: v1
kind: Service
metadata:
  name: test
spec:
  ports:
    - protocol: TCP
      port: 80
  externalIPs:
    - 10.0.0.1
`

	serviceWithDeniedExternalIP = `
apiVersion: v1
kind: Service
metadata:
  name: test
spec:
  ports:
    - protocol: TCP
      port: 80
  externalIPs:
    - 80.11.12.10
`
)

func newRequest(svcSpec, username string, groups []string) admission.Request {
	raw, err := yaml.YAMLToJSON([]byte(svcSpec))
	if err != nil {
		return admission.Request{}
	}

	req := admission.Request{
		AdmissionRequest: admissionv1beta1.AdmissionRequest{
			UID: "a2d5bf04-75e5-4f30-9ec6-e648611f22a0",
			UserInfo: authenticationv1.UserInfo{
				Username: username,
				Groups:   groups,
			},
			Kind:      metav1.GroupVersionKind{Group: "", Version: "v1", Kind: "Service"},
			Operation: "CREATE",
			Object: runtime.RawExtension{
				Raw: raw,
			},
		},
	}

	return req
}

func TestHandle(t *testing.T) {
	tc := []struct {
		name             string
		allowedIPs       []string
		allowedUsernames []string
		allowedGroups    []string
		serviceSpec      string
		userName         string
		groups           []string
		ExpectAllowed    bool
	}{
		{
			name:             "Create service without externalIP by denied user",
			allowedIPs:       []string{"10.0.0.0/8"},
			allowedUsernames: []string{"user2"},
			allowedGroups:    []string{"group2"},
			serviceSpec:      serviceWithoutExternalIP,
			userName:         "user1",
			groups:           []string{},
			ExpectAllowed:    true,
		},
		{
			name:             "Create service without externalIP by allowed user (by username)",
			allowedIPs:       []string{"10.0.0.0/8"},
			allowedUsernames: []string{"user1"},
			allowedGroups:    []string{"group2"},
			serviceSpec:      serviceWithoutExternalIP,
			userName:         "user1",
			groups:           []string{},
			ExpectAllowed:    true,
		},
		{
			name:             "Create service with allowed externalIP by denied user",
			allowedIPs:       []string{"10.0.0.0/8"},
			allowedUsernames: []string{"user2"},
			allowedGroups:    []string{"group2"},
			serviceSpec:      serviceWithAllowedExternalIP,
			userName:         "user1",
			groups:           []string{},
			ExpectAllowed:    false,
		},
		{
			name:             "Create service with allowed externalIP by allowed user (by group)",
			allowedIPs:       []string{"10.0.0.0/8"},
			allowedUsernames: []string{"user2"},
			allowedGroups:    []string{"group1"},
			serviceSpec:      serviceWithAllowedExternalIP,
			userName:         "user1",
			groups:           []string{"group1"},
			ExpectAllowed:    true,
		},
		{
			name:             "Create service with denied externalIP by denied user",
			allowedIPs:       []string{"10.0.0.0/8"},
			allowedUsernames: []string{"user2"},
			allowedGroups:    []string{"group2"},
			serviceSpec:      serviceWithDeniedExternalIP,
			userName:         "user1",
			groups:           []string{},
			ExpectAllowed:    false,
		},
		{
			name:             "Create service with denied externalIP by allowed user (by both username and group)",
			allowedIPs:       []string{"10.0.0.0/8"},
			allowedUsernames: []string{"user1"},
			allowedGroups:    []string{"group1"},
			serviceSpec:      serviceWithDeniedExternalIP,
			userName:         "user1",
			groups:           []string{"group1"},
			ExpectAllowed:    true,
		},
	}

	for _, tt := range tc {
		newServiceValidator, _ := NewServiceValidator(tt.allowedIPs, tt.allowedUsernames, tt.allowedGroups)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		s := scheme.Scheme
		corev1.AddToScheme(s)
		decoder, err := admission.NewDecoder(s)
		assert.NoError(t, err, "fail to create decorder")

		newServiceValidator.InjectDecoder(decoder)

		actualOutput := newServiceValidator.Handle(ctx, newRequest(tt.serviceSpec, tt.userName, tt.groups))
		assert.Equal(t, tt.ExpectAllowed, actualOutput.Allowed, "%s: expected allowed %v but got %v", tt.name, tt.ExpectAllowed, actualOutput.Allowed)
	}
}
