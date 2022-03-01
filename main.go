/*
Copyright 2020 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"os"

	flag "github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	// +kubebuilder:scaffold:imports

	"github.com/kubernetes-security/externalip-webhook/pkg/validator"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	_ = clientgoscheme.AddToScheme(scheme)

	// +kubebuilder:scaffold:scheme
}

func main() {
	var allowedCIDRs []string
	var allowedUsernames []string
	var allowedGroups []string
	var metricsAddr string
	var webhookPort int

	flag.IntVar(&webhookPort, "webhook-port", 9443, "Webhook port number")
	flag.StringVar(&metricsAddr, "metrics-addr", "0", "The address the metric endpoint binds to.")
	flag.StringSliceVar(&allowedCIDRs, "allowed-external-ip-cidrs", []string{}, "List of CIDR ranges allowed as External IPs in the service spec.")
	flag.StringSliceVar(&allowedUsernames, "allowed-usernames", []string{}, "List of usernames allowed to assign External IPs in the service spec.")
	flag.StringSliceVar(&allowedGroups, "allowed-groups", []string{}, "List of groups allowed to assign External IPs in the service spec.")
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:             scheme,
		MetricsBindAddress: metricsAddr,
		Port:               webhookPort,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	setupLog.Info("registering webhook...")
	serviceValidator, err := validator.NewServiceValidator(allowedCIDRs, allowedUsernames, allowedGroups)
	if err != nil {
		setupLog.Error(err, "problem registering webhook")
		os.Exit(1)
	}

	mgr.GetWebhookServer().Register("/validate-service", &webhook.Admission{Handler: serviceValidator})

	// +kubebuilder:scaffold:builder

	setupLog.Info("starting webhook...")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem starting webhook")
		os.Exit(1)
	}
}
