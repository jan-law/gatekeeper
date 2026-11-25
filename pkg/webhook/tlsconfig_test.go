package webhook

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	openshifttls "github.com/openshift/controller-runtime-common/pkg/tls"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
	restfake "k8s.io/client-go/rest/fake"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func tlsScheme(t *testing.T) *runtime.Scheme {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, configv1.AddToScheme(scheme))

	return scheme
}

// newFakeAPIServer serves discovery and the APIServer object.
func newFakeAPIServer(t *testing.T, serveOpenShiftAPI bool, tlsGroups ...string) *rest.Config {
	t.Helper()

	group := "apps"
	if serveOpenShiftAPI {
		group = configv1.GroupName
	}

	groupVersion := group + "/v1"
	apiGroups := fmt.Sprintf(
		`{"kind":"APIGroupList","apiVersion":"v1","groups":[`+
			`{"name":%q,"versions":[{"groupVersion":%q,"version":"v1"}],`+
			`"preferredVersion":{"groupVersion":%q,"version":"v1"}}]}`,
		group, groupVersion, groupVersion)

	profile := `{"type":"Modern"}`

	if len(tlsGroups) > 0 {
		profile = fmt.Sprintf(`{"type":"Custom","custom":{"groups":["%s"]}}`, strings.Join(tlsGroups, `","`))
	}

	return &rest.Config{
		Host: "https://api.example.test",
		Transport: restfake.CreateHTTPClient(func(r *http.Request) (*http.Response, error) {
			path := r.URL.Path

			var body string

			status := http.StatusOK

			switch {
			case path == "/api":
				body = `{"kind":"APIVersions","apiVersion":"v1","versions":["v1"]}`
			case path == "/apis":
				body = apiGroups
			case serveOpenShiftAPI && strings.HasSuffix(path, "/apiservers/"+openshifttls.APIServerName):
				body = `{"apiVersion":"config.openshift.io/v1","kind":"APIServer",` +
					`"metadata":{"name":"cluster"},"spec":{"tlsSecurityProfile":` + profile + `}}`
			case serveOpenShiftAPI && strings.HasPrefix(path, "/apis/"):
				body = `{"kind":"APIResourceList","apiVersion":"v1","groupVersion":"` +
					strings.TrimPrefix(path, "/apis/") +
					`","resources":[{"name":"apiservers","kind":"APIServer","namespaced":false}]}`
			case strings.HasPrefix(path, "/apis/"):
				status = http.StatusNotFound
				body = `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","code":404}`
			default:
				return nil, errors.New("unexpected path: " + path)
			}

			return &http.Response{
				StatusCode: status,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(body)),
			}, nil
		}).Transport,
	}
}

const (
	tls12CipherSuite = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	tlsGroupP384     = "secp384r1"
	tlsVersion12     = "1.2"
)

// tlsConfigFrom applies the resolved TLS options to an empty config.
func tlsConfigFrom(tlsOpts []func(*tls.Config)) *tls.Config {
	got := &tls.Config{}
	for _, opt := range tlsOpts {
		opt(got)
	}

	return got
}

func TestResolveTLSConfigFlagsTakePrecedence(t *testing.T) {
	tlsOpts, watchAPIServer, profile, err := ResolveTLSConfig(
		t.Context(), nil, nil, tlsVersion12, tls12CipherSuite, tlsGroupP384, "")
	require.NoError(t, err)

	assert.False(t, watchAPIServer, "no APIServer watcher when every setting comes from flags")
	assert.Equal(t, configv1.TLSProfileSpec{}, profile)

	got := tlsConfigFrom(tlsOpts)

	assert.Equal(t, uint16(tls.VersionTLS12), got.MinVersion)
	assert.Equal(t, []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}, got.CipherSuites)
	assert.Equal(t, []tls.CurveID{tls.CurveP384}, got.CurvePreferences)
}

func TestResolveTLSConfigUsesAPIServerProfile(t *testing.T) {
	tlsOpts, watchAPIServer, profile, err := ResolveTLSConfig(
		t.Context(), newFakeAPIServer(t, true), tlsScheme(t), tlsVersion12, "", "", "")
	require.NoError(t, err)

	assert.True(t, watchAPIServer)
	assert.Equal(t, configv1.TLSProfiles[configv1.TLSProfileModernType].Groups, profile.Groups)

	got := tlsConfigFrom(tlsOpts)

	assert.Equal(t, uint16(tls.VersionTLS12), got.MinVersion, "min version still comes from the flag")
	assert.NotEmpty(t, got.CurvePreferences)
	assert.NotEmpty(t, got.CipherSuites)
}

func TestResolveTLSConfigFlagOverridesAPIServerGroup(t *testing.T) {
	tlsOpts, watchAPIServer, _, err := ResolveTLSConfig(
		t.Context(), newFakeAPIServer(t, true), tlsScheme(t), tlsVersion12, "", tlsGroupP384, "")
	require.NoError(t, err)

	// Cipher suites still come from the APIServer, so the watcher stays enabled.
	assert.True(t, watchAPIServer)

	got := tlsConfigFrom(tlsOpts)

	assert.Equal(t, []tls.CurveID{tls.CurveP384}, got.CurvePreferences)
	assert.NotEmpty(t, got.CipherSuites)
}

func TestResolveTLSConfigNoAPIServerKeepsDefaults(t *testing.T) {
	tlsOpts, watchAPIServer, profile, err := ResolveTLSConfig(
		t.Context(), newFakeAPIServer(t, false), tlsScheme(t), "1.3", "", "", "")
	require.NoError(t, err)

	assert.False(t, watchAPIServer)
	assert.Equal(t, configv1.TLSProfileSpec{}, profile)

	got := tlsConfigFrom(tlsOpts)

	assert.Equal(t, uint16(tls.VersionTLS13), got.MinVersion, "1.3 default is kept when the APIServer is absent")
	assert.Empty(t, got.CipherSuites)
	assert.Empty(t, got.CurvePreferences)
}

func TestResolveTLSConfigInvalidValues(t *testing.T) {
	tests := []struct {
		name       string
		minVersion string
		cipher     string
		group      string
		wantErrIs  error
	}{
		{name: "invalid min version", minVersion: "bogus"},
		{name: "invalid groups", minVersion: tlsVersion12, group: "bogus-group", wantErrIs: errInvalidTLSGroups},
		{name: "invalid cipher suites", minVersion: tlsVersion12, cipher: "bogus-cipher", wantErrIs: errInvalidTLSCipherSuites},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, err := ResolveTLSConfig(
				t.Context(), nil, nil, tt.minVersion, tt.cipher, tt.group, "")
			require.Error(t, err)

			if tt.wantErrIs != nil {
				require.ErrorIs(t, err, tt.wantErrIs)
			}
		})
	}
}

func TestResolveTLSConfigTLS13SkipsCipherSuites(t *testing.T) {
	tlsOpts, _, _, err := ResolveTLSConfig(
		t.Context(), nil, nil, "1.3", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "", "")
	require.NoError(t, err)

	got := tlsConfigFrom(tlsOpts)

	assert.Equal(t, uint16(tls.VersionTLS13), got.MinVersion)
	assert.Empty(t, got.CipherSuites, "Go does not allow TLS 1.3 cipher suite tuning")
}

func TestFetchAPIServerTLSProfileFallback(t *testing.T) {
	gvr := schema.GroupResource{Group: configv1.GroupName, Resource: "apiservers"}

	tests := []struct {
		name string
		err  error
	}{
		{name: "not found", err: apierrors.NewNotFound(gvr, openshifttls.APIServerName)},
		{name: "not served", err: &meta.NoResourceMatchError{PartialResource: schema.GroupVersionResource{Group: configv1.GroupName, Resource: "apiservers"}}},
		{name: "forbidden", err: apierrors.NewForbidden(gvr, openshifttls.APIServerName, errors.New("denied"))},
		{name: "read error", err: errors.New("connection refused")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k8sClient := fakeclient.NewClientBuilder().
				WithScheme(tlsScheme(t)).
				WithInterceptorFuncs(interceptor.Funcs{
					Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
						return tt.err
					},
				}).
				Build()

			profile, watchable := fetchAPIServerTLSProfile(t.Context(), k8sClient)

			assert.False(t, watchable)
			assert.Equal(t, configv1.TLSProfileSpec{}, profile)
		})
	}
}

func TestFetchAPIServerTLSProfileSuccess(t *testing.T) {
	apiServer := &configv1.APIServer{
		ObjectMeta: metav1.ObjectMeta{Name: openshifttls.APIServerName},
		Spec: configv1.APIServerSpec{
			TLSSecurityProfile: &configv1.TLSSecurityProfile{Type: configv1.TLSProfileOldType},
		},
	}

	k8sClient := fakeclient.NewClientBuilder().WithScheme(tlsScheme(t)).WithObjects(apiServer).Build()

	profile, watchable := fetchAPIServerTLSProfile(t.Context(), k8sClient)

	assert.True(t, watchable)
	assert.Equal(t, configv1.TLSProfiles[configv1.TLSProfileOldType].Ciphers, profile.Ciphers)
}

func TestResolveTLSConfigParsesCommaSeparatedFlags(t *testing.T) {
	tlsOpts, _, _, err := ResolveTLSConfig(t.Context(), nil, nil, tlsVersion12,
		" TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 , ECDHE-RSA-AES256-GCM-SHA384,", " X25519 , secp384r1,,", "")
	require.NoError(t, err)

	got := tlsConfigFrom(tlsOpts)

	assert.Equal(t,
		[]uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
		got.CipherSuites)
	assert.Equal(t, []tls.CurveID{tls.X25519, tls.CurveP384}, got.CurvePreferences)
}

func TestResolveTLSConfigClientCA(t *testing.T) {
	tlsOpts, _, _, err := ResolveTLSConfig(t.Context(), nil, nil, tlsVersion12, "", "", "client-ca")
	require.NoError(t, err)
	require.Len(t, tlsOpts, 2)

	got := tlsConfigFrom(tlsOpts)

	assert.Equal(t, uint16(tls.VersionTLS12), got.MinVersion)
	assert.NotNil(t, got.VerifyConnection)
}
