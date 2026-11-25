package webhook

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	openshifttls "github.com/openshift/controller-runtime-common/pkg/tls"
	libgocrypto "github.com/openshift/library-go/pkg/crypto"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	// errInvalidTLSGroups marks an invalid --tls-groups value so the caller exits instead of using defaults.
	errInvalidTLSGroups = errors.New("invalid --tls-groups value")
	// errInvalidTLSCipherSuites marks an invalid --tls-cipher-suites value so the caller exits instead of using defaults.
	errInvalidTLSCipherSuites = errors.New("invalid --tls-cipher-suites value")
)

const apiServerTLSProfileTimeout = 10 * time.Second

// ResolveTLSConfig merges the TLS settings used by the webhook server. Flag values take precedence, then the
// APIServer TLS profile. The minimum TLS version always comes from --tls-min-version so the existing 1.3 default
// is preserved.
func ResolveTLSConfig(
	ctx context.Context, cfg *rest.Config, scheme *runtime.Scheme, minVersion, cipherSuites, groups, clientCAName string,
) (tlsOpts []func(*tls.Config), watchAPIServer bool, initialProfile configv1.TLSProfileSpec, err error) {
	minVersionID, err := ParseTLSVersion(minVersion)
	if err != nil {
		return nil, false, configv1.TLSProfileSpec{}, err
	}

	flagCiphers := splitCommaList(cipherSuites)
	flagGroups := splitCommaList(groups)

	spec := configv1.TLSProfileSpec{
		MinTLSVersion: configv1.TLSProtocolVersion(libgocrypto.TLSVersionToNameOrDie(minVersionID)),
		Ciphers:       flagCiphers,
	}

	for _, group := range flagGroups {
		spec.Groups = append(spec.Groups, configv1.TLSGroup(group))
	}

	if (len(spec.Groups) == 0 || len(spec.Ciphers) == 0) && cfg != nil {
		initialProfile, watchAPIServer = readAPIServerTLSProfile(ctx, cfg, scheme)

		if len(spec.Groups) == 0 {
			spec.Groups = initialProfile.Groups
		}

		if len(spec.Ciphers) == 0 {
			spec.Ciphers = initialProfile.Ciphers
		}
	}

	tlsOpt, unsupported := openshifttls.NewTLSConfigFromProfile(spec)

	if err := checkUnsupportedFlags(unsupported, flagGroups, flagCiphers); err != nil {
		return nil, false, configv1.TLSProfileSpec{}, err
	}

	if len(unsupported) > 0 {
		log.Info("Some APIServer TLS values are not supported and will be ignored", "values", unsupported)
	}

	if len(spec.Ciphers) > 0 && minVersionID == tls.VersionTLS13 {
		log.Info("TLS cipher suites are ignored for TLS 1.3", "cipherSuites", spec.Ciphers)
	}

	opts := []func(*tls.Config){tlsOpt}

	if clientCAName != "" {
		opts = append(opts, func(cfg *tls.Config) {
			cfg.VerifyConnection = GetCertNameVerifier()
		})
	}

	return opts, watchAPIServer, initialProfile, nil
}

// checkUnsupportedFlags returns an error when the TLS profile translation rejected a flag value.
func checkUnsupportedFlags(unsupported, flagGroups, flagCiphers []string) error {
	var badGroups, badCiphers []string

	for _, value := range unsupported {
		switch {
		case slices.Contains(flagGroups, value):
			badGroups = append(badGroups, value)
		case slices.Contains(flagCiphers, value):
			badCiphers = append(badCiphers, value)
		}
	}

	switch {
	case len(badGroups) > 0:
		return fmt.Errorf("%w: %v", errInvalidTLSGroups, badGroups)
	case len(badCiphers) > 0:
		return fmt.Errorf("%w: %v", errInvalidTLSCipherSuites, badCiphers)
	}

	return nil
}

// splitCommaList splits a flag value on commas, ignoring whitespace and empty entries.
func splitCommaList(values string) []string {
	return strings.Fields(strings.ReplaceAll(values, ",", " "))
}

func readAPIServerTLSProfile(
	ctx context.Context, cfg *rest.Config, scheme *runtime.Scheme,
) (profile configv1.TLSProfileSpec, watchable bool) {
	cfg = rest.CopyConfig(cfg)
	// Bounds RESTMapper discovery, which runs without the fetch context.
	cfg.Timeout = apiServerTLSProfileTimeout

	apiServerClient, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		log.Error(err, "Failed to create a client for the APIServer resource")

		return configv1.TLSProfileSpec{}, false
	}

	fetchCtx, cancel := context.WithTimeout(ctx, apiServerTLSProfileTimeout)
	defer cancel()

	return fetchAPIServerTLSProfile(fetchCtx, apiServerClient)
}

func fetchAPIServerTLSProfile(ctx context.Context, apiServerClient client.Client) (profile configv1.TLSProfileSpec, watchable bool) {
	profile, err := openshifttls.FetchAPIServerTLSProfile(ctx, apiServerClient)
	switch {
	case err == nil:
		return profile, true
	case meta.IsNoMatchError(err) || apierrors.IsNotFound(err):
		log.Info("The APIServer TLS profile is not served by this cluster; using Go TLS defaults")

		return configv1.TLSProfileSpec{}, false
	case apierrors.IsForbidden(err):
		log.Info("Access to the APIServer TLS profile is forbidden; using Go TLS defaults")

		return configv1.TLSProfileSpec{}, false
	default:
		log.Error(err, "Failed to read the APIServer TLS profile; using Go TLS defaults and skipping the watch")

		return configv1.TLSProfileSpec{}, false
	}
}
