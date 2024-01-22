package cockroachdb_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/testcontainers/testcontainers-go/modules/cockroachdb"
)

func TestCockroach(t *testing.T) {
	ctx := context.Background()

	t.Run("ping default database", func(t *testing.T) {
		container, err := cockroachdb.RunContainer(ctx)
		require.NoError(t, err)

		t.Cleanup(func() {
			err := container.Terminate(ctx)
			require.NoError(t, err)
		})

		conn, err := pgx.Connect(ctx, container.MustConnectionString(ctx))
		require.NoError(t, err)

		err = conn.Ping(ctx)
		require.NoError(t, err)
	})

	t.Run("ping custom database", func(t *testing.T) {
		container, err := cockroachdb.RunContainer(ctx, cockroachdb.WithDatabase("test"))
		require.NoError(t, err)

		t.Cleanup(func() {
			err := container.Terminate(ctx)
			require.NoError(t, err)
		})

		dsn, err := container.ConnectionString(ctx)
		require.NoError(t, err)

		u, err := url.Parse(dsn)
		require.NoError(t, err)
		require.Equal(t, "/test", u.Path)

		conn, err := pgx.Connect(ctx, dsn)
		require.NoError(t, err)

		err = conn.Ping(ctx)
		require.NoError(t, err)
	})

	t.Run("ping with tls", func(t *testing.T) {
		caCert, caKey := generateCA(t)
		nodeCert, nodeKey := generateNode(t, caCert, caKey)
		clientCert, clientKey := generateClient(t, caCert, caKey)

		container, err := cockroachdb.RunContainer(ctx,
			cockroachdb.WithTLS(cockroachdb.TLSConfig{
				CACert:     caCert,
				NodeCert:   nodeCert,
				NodeKey:    nodeKey,
				ClientCert: clientCert,
				ClientKey:  clientKey,
			}),
		)
		require.NoError(t, err)

		t.Cleanup(func() {
			err := container.Terminate(ctx)
			require.NoError(t, err)
		})

		cfg, err := pgx.ParseConfig(container.MustConnectionString(ctx))
		require.NoError(t, err)

		clientTLS, err := container.TLSConfig()
		require.NoError(t, err)
		cfg.TLSConfig = clientTLS

		conn, err := pgx.ConnectConfig(ctx, cfg)
		require.NoError(t, err)

		err = conn.Ping(ctx)
		require.NoError(t, err)

		err = conn.Ping(ctx)
		require.NoError(t, err)
	})
}

func generateCA(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	template := x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			CommonName: "Cockroach Test CA",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	caBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, caPrivKey.Public(), caPrivKey)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(caBytes)
	require.NoError(t, err)

	return caCert, caPrivKey
}

func generateNode(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey) ([]byte, []byte) {
	t.Helper()

	template := x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			CommonName: "node",
		},
		DNSNames: []string{"localhost"},
		IPAddresses: []net.IP{
			net.IPv4(127, 0, 0, 1),
			net.IPv6loopback,
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, certPrivKey.Public(), caKey)
	require.NoError(t, err)

	cert := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	certKey := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})

	return cert, certKey
}

func generateClient(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey) ([]byte, []byte) {
	t.Helper()

	template := x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			CommonName: "root",
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, certPrivKey.Public(), caKey)
	require.NoError(t, err)

	cert := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	certKey := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})

	return cert, certKey
}
