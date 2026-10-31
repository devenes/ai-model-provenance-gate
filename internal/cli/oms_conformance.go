package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/devenes/ai-model-provenance-gate/internal/oms"
	"github.com/devenes/ai-model-provenance-gate/internal/policy"
	"github.com/devenes/ai-model-provenance-gate/internal/signing"
	"github.com/devenes/ai-model-provenance-gate/internal/verification"
)

type multiStringFlag []string

func (m *multiStringFlag) String() string {
	return strings.Join(*m, ",")
}

func (m *multiStringFlag) Set(val string) error {
	*m = append(*m, val)
	return nil
}

func runOMSSignModel(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sign-model", flag.ContinueOnError)
	fs.SetOutput(stderr)
	method := fs.String("method", "key", "Signing method (key, certificate)")
	modelPath := fs.String("model-path", "", "Path to model directory or single file")
	outputBundle := fs.String("output-bundle", "", "Output Sigstore bundle path")
	privateKeyPath := fs.String("private-key", "", "PEM private key path")
	signingCertPath := fs.String("signing-cert", "", "PEM leaf signing certificate path")
	identityToken := fs.String("identity-token", "", "OIDC identity token for keyless Sigstore signing")
	useStaging := fs.Bool("use-staging", false, "Use Sigstore staging infrastructure")
	var certChains multiStringFlag
	var ignorePaths multiStringFlag
	fs.Var(&certChains, "cert-chain", "PEM intermediate/CA certificate path (repeatable)")
	fs.Var(&ignorePaths, "ignore-paths", "Path to exclude from signing (repeatable)")

	if err := fs.Parse(args); err != nil {
		return policy.ExitInvalid
	}
	_ = useStaging
	if strings.TrimSpace(*modelPath) == "" || strings.TrimSpace(*outputBundle) == "" {
		_, _ = fmt.Fprintln(stderr, "error: --model-path and --output-bundle are required")
		return policy.ExitInvalid
	}

	m := strings.ToLower(strings.TrimSpace(*method))
	if m == "sigstore" {
		_ = identityToken
		_, _ = fmt.Fprintln(stderr, "error: online keyless Fulcio/Rekor signing is not enabled in offline mode; use --method key or --method certificate")
		return policy.ExitFail
	}
	if strings.TrimSpace(*privateKeyPath) == "" {
		_, _ = fmt.Fprintln(stderr, "error: --private-key is required")
		return policy.ExitInvalid
	}

	priv, err := signing.LoadPrivateKeyFile(*privateKeyPath, "")
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: load private key: %v\n", err)
		return policy.ExitFail
	}
	// Per OMS v1.0 envelope.schema.json, signatures[].keyid is empty string by default.
	priv.KeyID = ""

	rawBundle, err := oms.SignModelPath(*modelPath, priv, oms.SignOptions{
		AsSigstoreBundle: true,
		Method:           m,
		SigningCertPath:  *signingCertPath,
		CertChainPaths:   certChains,
		IgnorePaths:      ignorePaths,
		OutputBundlePath: *outputBundle,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: sign-model failed: %v\n", err)
		return policy.ExitFail
	}

	if err := os.MkdirAll(filepath.Dir(*outputBundle), 0o755); err != nil {
		_, _ = fmt.Fprintf(stderr, "error: create output directory: %v\n", err)
		return policy.ExitFail
	}
	if err := os.WriteFile(*outputBundle, rawBundle, 0o600); err != nil {
		_, _ = fmt.Fprintf(stderr, "error: write output bundle: %v\n", err)
		return policy.ExitFail
	}

	_, _ = fmt.Fprintln(stdout, "Signing succeeded")
	return policy.ExitPass
}

func runOMSVerifyModel(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify-model", flag.ContinueOnError)
	fs.SetOutput(stderr)
	method := fs.String("method", "key", "Verification method (key, certificate, sigstore)")
	modelPath := fs.String("model-path", "", "Path to model directory or single file")
	bundlePath := fs.String("bundle", "", "Path to Sigstore bundle (.sig)")
	publicKeyPath := fs.String("public-key", "", "Path to PEM public key (for --method key)")
	certIdentity := fs.String("certificate-identity", "", "Expected SAN identity (for --method sigstore)")
	identityAlias := fs.String("identity", "", "Expected SAN identity (for --method sigstore)")
	certOIDCIssuer := fs.String("certificate-oidc-issuer", "", "Expected OIDC issuer (for --method sigstore)")
	identityProviderAlias := fs.String("identity-provider", "", "Expected OIDC issuer (for --method sigstore)")
	useStaging := fs.Bool("use-staging", false, "Use Sigstore staging infrastructure")
	ignoreUnsigned := fs.Bool("ignore-unsigned-files", false, "Allow extra unsigned files in model directory")
	var certChains multiStringFlag
	var ignorePaths multiStringFlag
	fs.Var(&certChains, "cert-chain", "PEM trust anchor / intermediate certificate path (repeatable)")
	fs.Var(&ignorePaths, "ignore-paths", "Path to exclude from verification (repeatable)")

	if err := fs.Parse(args); err != nil {
		return policy.ExitInvalid
	}
	_ = useStaging
	if strings.TrimSpace(*modelPath) == "" || strings.TrimSpace(*bundlePath) == "" {
		_, _ = fmt.Fprintln(stderr, "error: --model-path and --bundle are required")
		return policy.ExitInvalid
	}

	effectiveIdentity := strings.TrimSpace(*certIdentity)
	if effectiveIdentity == "" {
		effectiveIdentity = strings.TrimSpace(*identityAlias)
	}
	effectiveIssuer := strings.TrimSpace(*certOIDCIssuer)
	if effectiveIssuer == "" {
		effectiveIssuer = strings.TrimSpace(*identityProviderAlias)
	}

	m := strings.ToLower(strings.TrimSpace(*method))
	opts := oms.VerifyOptions{
		Mode:                  oms.ModeNative,
		Method:                m,
		CertChainPaths:        certChains,
		CertificateIdentity:   effectiveIdentity,
		CertificateOIDCIssuer: effectiveIssuer,
		IgnorePaths:           ignorePaths,
		IgnoreUnsignedFiles:   *ignoreUnsigned,
	}

	if m == "key" {
		if strings.TrimSpace(*publicKeyPath) == "" {
			_, _ = fmt.Fprintln(stderr, "error: --public-key is required for --method key")
			return policy.ExitInvalid
		}
		pub, err := signing.LoadPublicKeyFile(*publicKeyPath, "", "oms-verifier")
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error: load public key: %v\n", err)
			return policy.ExitFail
		}
		opts.TrustedSigners = []verification.TrustedSignerRule{
			{
				ID:        "oms-key",
				Name:      "OMS Public Key",
				PublicKey: pub,
			},
		}
	}

	res, err := oms.VerifyModelPath(ctx, *modelPath, *bundlePath, opts)
	if err != nil || res.Status != verification.StatusVerified {
		_, _ = fmt.Fprintf(stderr, "error: verify-model failed (status=%s): %v (%s)\n", res.Status, err, res.Reason)
		return policy.ExitFail
	}

	_, _ = fmt.Fprintln(stdout, "Verification succeeded")
	return policy.ExitPass
}
