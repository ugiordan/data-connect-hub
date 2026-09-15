package tls

import (
	"context"
	cryptotls "crypto/tls"
	"reflect"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestResolveAppliesTLSProfileAccordingToAdherence(t *testing.T) {
	tests := []struct {
		name           string
		adherence      configv1.TLSAdherencePolicy
		wantMinVersion uint16
	}{
		{
			name:           "no opinion uses intermediate defaults",
			adherence:      configv1.TLSAdherencePolicyNoOpinion,
			wantMinVersion: cryptotls.VersionTLS12,
		},
		{
			name:           "legacy components only uses intermediate defaults",
			adherence:      configv1.TLSAdherencePolicyLegacyAdheringComponentsOnly,
			wantMinVersion: cryptotls.VersionTLS12,
		},
		{
			name:           "strict adherence uses the cluster profile",
			adherence:      configv1.TLSAdherencePolicyStrictAllComponents,
			wantMinVersion: cryptotls.VersionTLS10,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			apiServer := &configv1.APIServer{
				ObjectMeta: metav1.ObjectMeta{Name: apiServerName},
				Spec: configv1.APIServerSpec{
					TLSSecurityProfile: &configv1.TLSSecurityProfile{Type: configv1.TLSProfileOldType},
					TLSAdherence:       test.adherence,
				},
			}

			result, err := resolve(context.Background(), newTLSClient(t, apiServer))
			if err != nil {
				t.Fatalf("resolve() returned an error: %v", err)
			}
			if !reflect.DeepEqual(result.ProfileSpec, *configv1.TLSProfiles[configv1.TLSProfileOldType]) {
				t.Fatalf("ProfileSpec = %#v, want the observed Old profile", result.ProfileSpec)
			}
			if result.AdherencePolicy != test.adherence {
				t.Fatalf("AdherencePolicy = %q, want %q", result.AdherencePolicy, test.adherence)
			}

			config := &cryptotls.Config{}
			for _, option := range result.TLSOpts {
				option(config)
			}
			if config.MinVersion != test.wantMinVersion {
				t.Fatalf("MinVersion = %d, want %d", config.MinVersion, test.wantMinVersion)
			}
		})
	}
}

func TestResolveRegistersWatcherWhenAPIServerIsNotFound(t *testing.T) {
	result, err := resolve(context.Background(), newTLSClient(t))
	if err != nil {
		t.Fatalf("resolve() returned an error: %v", err)
	}
	if !result.ProfileFetched {
		t.Fatal("ProfileFetched = false, want true so the watcher can observe APIServer creation")
	}
}

func newTLSClient(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := configv1.Install(scheme); err != nil {
		t.Fatalf("installing OpenShift config scheme: %v", err)
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
}
