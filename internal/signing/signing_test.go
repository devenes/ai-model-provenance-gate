package signing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMultiCurveECDSAAndRSASigning(t *testing.T) {
	payload := []byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"model","digest":{"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}],"predicateType":"https://model_signing/signature/v1.0","predicate":{}}`)
	pae := DSSEPAE(InTotoPayloadType, payload)

	curves := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-521", elliptic.P521()},
	}

	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			privKey, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatalf("generate %s: %v", tc.name, err)
			}
			privDER, err := x509.MarshalPKCS8PrivateKey(privKey)
			if err != nil {
				t.Fatalf("marshal priv: %v", err)
			}
			pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
			if err != nil {
				t.Fatalf("marshal pub: %v", err)
			}
			privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
			pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

			priv, err := ParsePrivateKeyPEM(privPEM, "")
			if err != nil {
				t.Fatalf("parse priv: %v", err)
			}
			pub, err := ParsePublicKeyPEM(pubPEM, "", tc.name)
			if err != nil {
				t.Fatalf("parse pub: %v", err)
			}

			env, err := SignDSSE(InTotoPayloadType, payload, priv)
			if err != nil {
				t.Fatalf("SignDSSE: %v", err)
			}
			_, rawP, err := verifyEnvelopeWithSingleKeyAndReturn(env, pub, pae)
			if err != nil || string(rawP) != string(payload) {
				t.Fatalf("verify failed: %v", err)
			}
		})
	}

	t.Run("RSA-2048", func(t *testing.T) {
		rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generate rsa: %v", err)
		}
		privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaPriv)})
		pubDER, _ := x509.MarshalPKIXPublicKey(&rsaPriv.PublicKey)
		pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

		priv, err := ParsePrivateKeyPEM(privPEM, "")
		if err != nil {
			t.Fatalf("parse rsa priv: %v", err)
		}
		pub, err := ParsePublicKeyPEM(pubPEM, "", "rsa")
		if err != nil {
			t.Fatalf("parse rsa pub: %v", err)
		}
		env, err := SignDSSE(InTotoPayloadType, payload, priv)
		if err != nil {
			t.Fatalf("SignDSSE rsa: %v", err)
		}
		if _, _, err := verifyEnvelopeWithSingleKeyAndReturn(env, pub, pae); err != nil {
			t.Fatalf("verify rsa failed: %v", err)
		}
	})
}

func verifyEnvelopeWithSingleKeyAndReturn(env DSSEEnvelope, pub *PublicKey, _ []byte) (DSSEEnvelope, []byte, error) {
	raw, err := verifyEnvelopeWithSingleKey(env, pub)
	return env, raw, err
}

func TestCertificateChainValidationAndNegativeCases(t *testing.T) {
	now := time.Now().UTC()
	payload := []byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"model","digest":{"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}],"predicateType":"https://model_signing/signature/v1.0","predicate":{}}`)

	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-root-ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create root cert: %v", err)
	}
	rootCert, _ := x509.ParseCertificate(rootDER)

	intKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	intTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "test-int-ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	intDER, err := x509.CreateCertificate(rand.Reader, intTmpl, rootCert, &intKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create int cert: %v", err)
	}
	intCert, _ := x509.ParseCertificate(intDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "test-leaf"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, intCert, &leafKey.PublicKey, intKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	leafCert, _ := x509.ParseCertificate(leafDER)

	leafPrivDER, _ := x509.MarshalPKCS8PrivateKey(leafKey)
	leafPriv, err := ParsePrivateKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: leafPrivDER}), "")
	if err != nil {
		t.Fatalf("parse leaf priv: %v", err)
	}

	chain, err := ValidateSigningCertificate(leafCert, []*x509.Certificate{intCert, rootCert}, leafPriv, now)
	if err != nil {
		t.Fatalf("ValidateSigningCertificate: %v", err)
	}
	env, err := SignDSSE(InTotoPayloadType, payload, leafPriv)
	if err != nil {
		t.Fatalf("SignDSSE: %v", err)
	}
	bundle, err := WrapInSigstoreCertificateBundle(env, chain)
	if err != nil {
		t.Fatalf("WrapInSigstoreCertificateBundle: %v", err)
	}
	rawBundle, _ := json.Marshal(bundle)

	// 1. Valid verification against root CA
	if _, _, _, err := VerifyCertificateBundle(rawBundle, []*x509.Certificate{rootCert}, now); err != nil {
		t.Fatalf("expected valid cert bundle verification, got %v", err)
	}

	// 2. Expired verification time -> fail
	if _, _, _, err := VerifyCertificateBundle(rawBundle, []*x509.Certificate{rootCert}, now.Add(48*time.Hour)); err == nil {
		t.Fatalf("expected failure for expired certificate")
	}

	// 3. Not-yet-valid verification time -> fail
	if _, _, _, err := VerifyCertificateBundle(rawBundle, []*x509.Certificate{rootCert}, now.Add(-48*time.Hour)); err == nil {
		t.Fatalf("expected failure for not-yet-valid certificate")
	}

	// 4. Missing codeSigning EKU -> fail on both ValidateSigningCertificate and VerifyCertificateBundle
	noEKUTmpl := *leafTmpl
	noEKUTmpl.ExtKeyUsage = nil
	noEKUDER, _ := x509.CreateCertificate(rand.Reader, &noEKUTmpl, intCert, &leafKey.PublicKey, intKey)
	noEKUCert, _ := x509.ParseCertificate(noEKUDER)
	if _, err := ValidateSigningCertificate(noEKUCert, []*x509.Certificate{intCert}, leafPriv, now); err == nil {
		t.Fatalf("expected ValidateSigningCertificate to reject cert without codeSigning EKU")
	}
	noEKUBundle, _ := WrapInSigstoreCertificateBundle(env, []*x509.Certificate{noEKUCert, intCert})
	rawNoEKU, _ := json.Marshal(noEKUBundle)
	if _, _, _, err := VerifyCertificateBundle(rawNoEKU, []*x509.Certificate{rootCert}, now); err == nil {
		t.Fatalf("expected VerifyCertificateBundle to reject cert without codeSigning EKU")
	}
}

func TestVerifyHistoricalAndPositiveCertBundles(t *testing.T) {
	base := "/Users/enes/.gemini/antigravity/brain/8bc08c95-7b5e-433d-9c76-7eb5fcbe0d10/scratch/model-signing-spec/conformance/test/test-cases/verify"
	if _, err := os.Stat(base); err != nil {
		t.Skip("scratch conformance fixtures not present")
	}

	histBundle, err := os.ReadFile(filepath.Join(base, "historical/historical-v1.1.0-certificate/bundle.sig"))
	if err != nil {
		t.Fatalf("read hist bundle: %v", err)
	}
	histCA, err := os.ReadFile(filepath.Join(base, "historical/historical-v1.1.0-certificate/verify-material/ca-cert.pem"))
	if err != nil {
		t.Fatalf("read hist ca: %v", err)
	}
	caCerts, err := ParseCertificatesPEM(histCA)
	if err != nil {
		t.Fatalf("parse hist ca: %v", err)
	}
	if _, _, _, err := VerifyCertificateBundle(histBundle, caCerts, time.Now().UTC()); err != nil {
		t.Fatalf("VerifyCertificateBundle historical-v1.1.0-certificate failed: %v", err)
	}

	sigBundle, err := os.ReadFile(filepath.Join(base, "historical/historical-v1.1.0-sigstore/bundle.sig"))
	if err != nil {
		t.Fatalf("read sigstore bundle: %v", err)
	}
	if _, _, _, err := VerifySigstoreBundle(sigBundle, "stefanb@us.ibm.com", "https://sigstore.verify.ibm.com/oauth2", nil); err != nil {
		t.Fatalf("VerifySigstoreBundle historical-v1.1.0-sigstore failed: %v", err)
	}
	// Wrong identity -> fail
	if _, _, _, err := VerifySigstoreBundle(sigBundle, "wrong@example.com", "https://sigstore.verify.ibm.com/oauth2", nil); err == nil {
		t.Fatalf("expected failure for wrong Sigstore SAN identity")
	}
	// Wrong issuer -> fail
	if _, _, _, err := VerifySigstoreBundle(sigBundle, "stefanb@us.ibm.com", "https://accounts.google.com", nil); err == nil {
		t.Fatalf("expected failure for wrong Sigstore OIDC issuer")
	}
}
