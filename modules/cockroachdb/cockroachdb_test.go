package cockroachdb_test

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/url"
	"testing"

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
			cockroachdb.WithTLS(caCert, nodeCert, nodeKey),
		)
		require.NoError(t, err)

		t.Cleanup(func() {
			err := container.Terminate(ctx)
			require.NoError(t, err)
		})

		cfg, err := pgx.ParseConfig(container.MustConnectionString(ctx))
		require.NoError(t, err)
		cfg.TLSConfig = generateClientTLS(t, caCert, clientCert, clientKey)

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

	certBytes := []byte(`
-----BEGIN CERTIFICATE-----
MIIDJTCCAg2gAwIBAgIQVlrtHFsUOTU0RMol4gj5bzANBgkqhkiG9w0BAQsFADAr
MRIwEAYDVQQKEwlDb2Nrcm9hY2gxFTATBgNVBAMTDENvY2tyb2FjaCBDQTAeFw0y
NDAxMjEwOTExMDdaFw0zNDAxMjkwOTExMDdaMCsxEjAQBgNVBAoTCUNvY2tyb2Fj
aDEVMBMGA1UEAxMMQ29ja3JvYWNoIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAu7j0eI4NLG/2FF2ikp6kh5apJSJR5QIlH+w3MBBxj5HUh6xN3xIk
LcOzQbdMNvYkPS1WIC4FQvLW+YdONRf84O5eUPKVAWKsaasN3dON2R7WYJM2Q3Pi
qvAMhzIrDkmYOf+2r6/s2GOsTmSBuvjYml38HUp5F5fekvUIxvDkiZWOrGFTTUwb
NijPSklSHxivoprZlcbAZLHJbc7g2RxFb0UghwJNl7zI1vCFdzh5h7/gJVv9NXk7
StoiHruWvQLnO0OZGomEPZPUwcyTqEz9l25vHhmpdq2eGLNetmwI0WxIeRTn4MK+
68fg9ujSaxbxs/KDyMkWt7wIveAZGvFeZQIDAQABo0UwQzAOBgNVHQ8BAf8EBAMC
AuQwEgYDVR0TAQH/BAgwBgEB/wIBATAdBgNVHQ4EFgQUIDADpWqcC3mGg0+xgUbd
04gfLf8wDQYJKoZIhvcNAQELBQADggEBALWAaemHQXA/iOZhunlA+tDScQsLMfJC
6LteD6nY7DMg/HeUr4s7sM0PGZ5eGdn+tTH/I+c6IR2dzDE7g1hxcBTo1FquFPlW
2eh1+/H1SwFlSwEY+gUs+tVu2fe0HmrRMLOrlNOfRzfk8TYzCZGxU6Zy/0NeTqE1
Iwj5y0/QBBO9DfnAgKHS0n6/r4mgZHgxvM3rA/fqQvJvJKUCYyodC4Ti5GkaJUkt
1+KbbmAFuArSnA70TObNNACaHlE5FrqEJ1xXSLu0V9iOAXMJrpyN8HwPu+9/V3JU
I7DOeip7G8oeYzawjM2n+h4SB+kSlgpvoW3zzSB9owCXKoGR7jeY1Uo=
-----END CERTIFICATE-----`)

	block, _ := pem.Decode(certBytes)
	caCert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	keyBytes := []byte(`
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAu7j0eI4NLG/2FF2ikp6kh5apJSJR5QIlH+w3MBBxj5HUh6xN
3xIkLcOzQbdMNvYkPS1WIC4FQvLW+YdONRf84O5eUPKVAWKsaasN3dON2R7WYJM2
Q3PiqvAMhzIrDkmYOf+2r6/s2GOsTmSBuvjYml38HUp5F5fekvUIxvDkiZWOrGFT
TUwbNijPSklSHxivoprZlcbAZLHJbc7g2RxFb0UghwJNl7zI1vCFdzh5h7/gJVv9
NXk7StoiHruWvQLnO0OZGomEPZPUwcyTqEz9l25vHhmpdq2eGLNetmwI0WxIeRTn
4MK+68fg9ujSaxbxs/KDyMkWt7wIveAZGvFeZQIDAQABAoIBABnZ2Yi0fynsbSXW
0yl/wUaOv9JGTKLNzdD8lYj/6rOLsInSd5LNi7/loEzfchZrhQgLsz2RONZEXMhW
ErYLDJ7pFIHvNgfPz9BpZupyVKlersTz4NgfIErL7d28UeOQzO7HwR+miWYvK65L
9vWJiUKQyMQ72jsehd8U8VV8HOy5OFcPT0dIEvlcjSKa22n65XZqgMray1UlQr98
1DI2bxBk37Aif9RLkzBbYzh/Hvc5Cj0Qn2fzlyX64Mh4zNMdTRWasCgUcNRxrNoo
b4sUQfy5Q+QeCBi924URE5utmmDVcPrLhDSCg4LvUro9ksUczCAzy23CqyYx8XgU
pB3PM+ECgYEA4zEYGsMQp3dfTSenkKo70xt0UlgVgBgYD7p1DxbQFAdg+SDNe+Js
5kXpnowWkpryiykPmYo8Yr2lUFyhfZQdPmOdj44hwuz6tkfaWmnR2/iodKdj8m/+
ntto7xmE2UnUAREPOlxwrjOchxHKGDdVtcsXiNcF4wGEEV+9Dpu6+H0CgYEA04ak
aCYtNJAGkMR8ihdjnTT55zhfEhCeYWCJABt2HA0muctL0yHiYT/bQl9kvyzLeaGI
QYAX97zU3XaaumR9Ybt86fSpFXNcLmTrSFHqxtKBUOlPKsOvakPiD0MBnvADkChT
xLgfzP90+DdQrdC22G5nM7663XSpuNlh7Aw8ygkCgYEAl1a0v98A0Q1rpnGr5WoA
v/eh3NhgOhvSq2eBYrPHmA/yQQHg341NDXe0z7BxuOcOejS394dmAkBiRs3tpUFs
2YpyApajVr2VpKbohSHIcceKL2rx4SVJb3ioxd0x6ayMVMmQY0gAp4op0q++97Kk
nZzT6IuTmEwCNbCYt4p1WeECgYBGqvnsTazWnbOD1BEjdXLzR4qiBARHHcQ8FitP
HN2Vu5MPiWrYq75c7R+MiiA3eni0NxI1h9z6CF05a/F/iikVaLTv2KxQnUzTtyWf
8LY2HIfVh0zKpbvKDcnNfX5iIh+ensp1s2n0a/ghISHUICGmJyRVdkgpylsVhZKg
cOoyOQKBgCRKNAkT2ManZjoYp2Emm8rI4vchYqT78lWFgwhK7g4MCvMjCX5GzAYk
IkTyYx5SbPVnUe9SMXngJPnAbHk33O1EO2z0luMYwqenqJI0WhD7sEUZaNb54Rkm
ai39fzAHww3qoZJPqN8iJP2SeFFeWkcH6Ehct5oyesLbQtc1UGyt
-----END RSA PRIVATE KEY-----`)

	block, _ = pem.Decode(keyBytes)
	caKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	require.NoError(t, err)

	return caCert, caKey

	// template := x509.Certificate{
	// 	SerialNumber: big.NewInt(2019),
	// 	Subject: pkix.Name{
	// 		CommonName:   "Testcontainers CA",
	// 		Organization: []string{"Testcontainers"},
	// 	},
	// 	NotBefore:             time.Now().Add(-time.Hour),
	// 	NotAfter:              time.Now().Add(time.Hour),
	// 	KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	// 	BasicConstraintsValid: true,
	// 	IsCA:                  true,
	// }

	// caPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	// require.NoError(t, err)

	// caBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, caPrivKey.Public(), caPrivKey)
	// require.NoError(t, err)

	// fmt.Printf("CA:\n%s\n", pem.EncodeToMemory(&pem.Block{
	// 	Type:  "CERTIFICATE",
	// 	Bytes: caBytes,
	// }))

	// caCert, err := x509.ParseCertificate(caBytes)
	// require.NoError(t, err)

	// return caCert, caPrivKey
}

func generateNode(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey) ([]byte, []byte) {
	t.Helper()

	cert := []byte(`
-----BEGIN CERTIFICATE-----
MIIDVzCCAj+gAwIBAgIRALY2atWI/49jIc6gRLCKN0AwDQYJKoZIhvcNAQELBQAw
KzESMBAGA1UEChMJQ29ja3JvYWNoMRUwEwYDVQQDEwxDb2Nrcm9hY2ggQ0EwHhcN
MjQwMTIxMTAzNTQ1WhcNMjkwMTI1MTAzNTQ1WjAjMRIwEAYDVQQKEwlDb2Nrcm9h
Y2gxDTALBgNVBAMTBG5vZGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQDDvP4UI8s5tTPF+zUlKEfD6cxZBrdIXc+JtgbHm7BcKrSqseSnghG4vxXx8HFi
qAH5NiEbXNd01oUjPVRhlyKl3C9mv8B8EinNZqqGJ/+0jz6mUMCW9LnVFHUn70Z/
l5BnI+zkjvkiJ2CBXyeeBg2UfcaePa5FhyyY0QSjtMutWxIOuGpcwi0pFnpxsMk0
lSwdLcPxYrZ3MrAz/fQ/q/o6r4A0GxZVU6gMiC8BFYDuVdMfPjyqKlQW/13qzE/i
kiqBIG4VTCWjmFqbAYkSzhtnjfwdfN/hO2A12417mgIdLIyMZMl8m6+usnBVEyCE
XYAq3+d71HPSFvCLWx1iNKZlAgMBAAGjfjB8MA4GA1UdDwEB/wQEAwIFoDAdBgNV
HSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwHwYDVR0jBBgwFoAUIDADpWqcC3mG
g0+xgUbd04gfLf8wKgYDVR0RBCMwIYIJbG9jYWxob3N0gg5yY3Jvd2UtZGVza3Rv
cIcEfwAAATANBgkqhkiG9w0BAQsFAAOCAQEAAATc/LTka22XwtJJf++Uv3V7Rfkw
olKv1Dhg2fYC8OKsXJcM1jNypBxPvDLUF3x1k+/lBDPPk01y38QzaRMloXpAdi1j
GjwZ3AIjU9TPLjtfzfpK7nXpaxLVBM0RRlszmSerYg0xwnBh5E0TaHMj9SiMGqR1
mNy4KVsVcfoC7VhDweXQTFhp17TmWRsJMmRxTCxtAThLOiHekRzHhGe7tM+Bz8Pv
3nEjRRHTLU9C4I0E0SXoXJVqn95vCejZuXBgvciIddeZE1M3GJNtFrVQGAJXIi4N
+K6Ld2nCVQT+dyLo2UYLPxtM8oJf7NJfIsZi4KFwg0eppsRY789vc+R+Ow==
-----END CERTIFICATE-----`)

	key := []byte(`
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAw7z+FCPLObUzxfs1JShHw+nMWQa3SF3PibYGx5uwXCq0qrHk
p4IRuL8V8fBxYqgB+TYhG1zXdNaFIz1UYZcipdwvZr/AfBIpzWaqhif/tI8+plDA
lvS51RR1J+9Gf5eQZyPs5I75IidggV8nngYNlH3Gnj2uRYcsmNEEo7TLrVsSDrhq
XMItKRZ6cbDJNJUsHS3D8WK2dzKwM/30P6v6Oq+ANBsWVVOoDIgvARWA7lXTHz48
qipUFv9d6sxP4pIqgSBuFUwlo5hamwGJEs4bZ438HXzf4TtgNduNe5oCHSyMjGTJ
fJuvrrJwVRMghF2AKt/ne9Rz0hbwi1sdYjSmZQIDAQABAoIBACOTznrKpr2ueeKa
bmZ6k9DARixIVDgLFRXqyACwA7Y87Om5u93WfnIeCVcYZQORlgo+FHZswZyzATAO
ja/PULTk+JisccgbZQ24g3Yu/wNKphCEzPyjLsPUHBdOHnpCijS1CvHgKthSX/Aj
44eNghpjYh6RB4QLtcdw9m7rBbpUaaZcp2nouwzWN08J1Ys4n1FG4ty9mmPyaP4r
vKvMaloQX8iExA6bgbkqvFyy+elWSRvt/4GlwPWp7Zw8HajSp26bDtAku2EZ83UV
oI/aTi9Kfce/iwj2SCTZuyGBM+u9efvgu3V9WP2N/y521PdcXLbaTtGC1NrJSpcu
UfNCl2ECgYEA8uGtnXmZHtuVWUK4jbzgEe+o0gHdbWcQT6QMzQHtrzL6oO8Ed3kG
AM5VXa73BcG+egbJ4QI8xtrq5ALbS2laajCdav9BDKSVAoBfqNWLWDr7o9BbOzS9
UlVj6TKxv0KXfwC3G8Qq2wQwZ9kwGpmn83M+PAQgtMblyvxuzQs8JAcCgYEAzk92
0Y9tuGQr77o00v+90OVZL8BnC3rMTqtZR77WZxZDBDcQgTdvLAreSE6F1uQImH05
JCGKHyCuc+2T9sj8QkO8UcKVFGaSHi9piMhJ2oWdlUmUFk6XecerZG4fVVDWmy9L
hbMX+hV39aXhOujKF+jS5B8fwHhn4ELpXeNWfzMCgYEApCPD8wJ0apg3DEW893zH
aRev3Y0JGaBnM4tIY1uER7yKCCy/tgYB+pV2t4NAyZEvqsPftsKOVE0qJMGRdhtS
0STdnau3SFYJpdEf1LfMHepumTx8Cz0PHQ88ICL0YK8eNuRC2u7tj2n7VJNAoRlq
mWouity3RbSNI2sJbmTDVg0CgYBiRJdj2d15Jr2GwjrHBelzxspkZFCwtxz5m8Q6
2DtnfsMNDu1dnvnlEIgwCLbXVGaDu6GsBA22JerybQc9VR5SsdDRYM2BmhmfJxYt
gLkszNfyc8mFlomwB9srSwjBqm+OG0jtthCFnhQ1fX16gcdA/DT3U5vcIX3Y5AYk
IlTg4QKBgGPectzTtutQPPp1bpxC/LR2VfXdwvtrMl03DVWMbk2kpJgGCDXTOusd
7lY7QCZjQbNgwxG/MSCrsT6XsBfX8y8MmslFC/nvejmWsYzPAfAbwcUNL0qDSVaV
20KmrSqHu6NSx36/M4W5AasBZTB/Xvp+FOJt7kq5+dZzsKieNkAd
-----END RSA PRIVATE KEY-----`)

	return cert, key

	// template := x509.Certificate{
	// 	SerialNumber: big.NewInt(2019),
	// 	Subject: pkix.Name{
	// 		CommonName: "node",
	// 	},
	// 	DNSNames: []string{"localhost"},
	// 	IPAddresses: []net.IP{
	// 		net.IPv4(127, 0, 0, 1),
	// 		net.IPv6loopback,
	// 	},
	// 	NotBefore: time.Now().Add(-time.Hour),
	// 	NotAfter:  time.Now().Add(time.Hour),
	// 	KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	// 	ExtKeyUsage: []x509.ExtKeyUsage{
	// 		x509.ExtKeyUsageServerAuth,
	// 		x509.ExtKeyUsageClientAuth,
	// 	},
	// 	BasicConstraintsValid: true,
	// }

	// certPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	// require.NoError(t, err)

	// certBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, certPrivKey.Public(), caKey)
	// require.NoError(t, err)

	// cert := pem.EncodeToMemory(&pem.Block{
	// 	Type:  "CERTIFICATE",
	// 	Bytes: certBytes,
	// })
	// certKey := pem.EncodeToMemory(&pem.Block{
	// 	Type:  "RSA PRIVATE KEY",
	// 	Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	// })

	// fmt.Printf("Node:\n%s\n", cert)

	// return cert, certKey
}

func generateClient(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey) ([]byte, []byte) {
	t.Helper()

	cert := []byte(`
-----BEGIN CERTIFICATE-----
MIIDITCCAgmgAwIBAgIRAN10SL5M8RLHfJC7O69Yb24wDQYJKoZIhvcNAQELBQAw
KzESMBAGA1UEChMJQ29ja3JvYWNoMRUwEwYDVQQDEwxDb2Nrcm9hY2ggQ0EwHhcN
MjQwMTIxMDkxMTU2WhcNMjkwMTI1MDkxMTU2WjAjMRIwEAYDVQQKEwlDb2Nrcm9h
Y2gxDTALBgNVBAMTBHJvb3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQDIYKRToKJJ9UIputvWekYIodRBukpVEfUosQHiGkJgX4AlrnVAq0Y3Mp4QT2Ki
Gsjn1wlZCnjn89I1HfaUfSrH9pF7bGjo9wLoyj4TBil5EGMcbvn0MiktNhIWWGEo
0u51FXEOMXrVcZFa0Ft1YOcJFYWW0wSM7C7cIjYq2M/bTttvehZdMooLzgg/Eqou
0HNzJ0+gODSf8GkeXGPWAKTh75QjAxofqpCAwcWoPPkEms297VCrm5RkTmvcGvsD
+6yApHjR5CYxJu65f5U9BedLlC0T0L6NbQWVmh2q6+t/xVN5mjpycGJmhnY6Lds3
JLCAbfDVlX1VZqON6UM39zGXAgMBAAGjSDBGMA4GA1UdDwEB/wQEAwIFoDATBgNV
HSUEDDAKBggrBgEFBQcDAjAfBgNVHSMEGDAWgBQgMAOlapwLeYaDT7GBRt3TiB8t
/zANBgkqhkiG9w0BAQsFAAOCAQEAX1P3ruq87eQ0Uod6GghfJ+PfbndfGNvrTqhl
4pSQHdksu2kLz2IXkOc2xK/Du33O5489y8/DxgEomNiKWOuf+OTM9WkOD4mgMI2b
PId2rUWNNjs+uf/6QujFHcftaVm1bCsxrmpNTqCwFSS0RX23p7hGw5g0gIp19gfV
QcDMjvvQUPSSY02CVM0M/gnb2dlfsomVGiNc4J4785lTxrbKspXApvKxrwLKMoae
Zd4Go6rwaUs38UPrSsONyf+o1qk2nF6dl8+B16WNEB4CGuAsZkWbrCWdvraGoGUF
aizXkYNgeVdNamo/i1SATb3aqMCLWsBQvPIsiEJpyfgbOOJZKQ==
-----END CERTIFICATE-----`)
	key := []byte(`
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAyGCkU6CiSfVCKbrb1npGCKHUQbpKVRH1KLEB4hpCYF+AJa51
QKtGNzKeEE9iohrI59cJWQp45/PSNR32lH0qx/aRe2xo6PcC6Mo+EwYpeRBjHG75
9DIpLTYSFlhhKNLudRVxDjF61XGRWtBbdWDnCRWFltMEjOwu3CI2KtjP207bb3oW
XTKKC84IPxKqLtBzcydPoDg0n/BpHlxj1gCk4e+UIwMaH6qQgMHFqDz5BJrNve1Q
q5uUZE5r3Br7A/usgKR40eQmMSbuuX+VPQXnS5QtE9C+jW0FlZodquvrf8VTeZo6
cnBiZoZ2Oi3bNySwgG3w1ZV9VWajjelDN/cxlwIDAQABAoIBAQCIbjS0s/SLwq/v
1ciE+e/hRL5OmlauIXH46LxNhG+ZSqzn+ybehz9hqdcxZ7vSf8Y3BJTayWSVGdAQ
Vnxjke2lBN79WEz+AeE7OyiUr2dhhKTW4UDS4axjmiMqj7Zno2a01YqKjWoDFjZP
zPnYq8fiyYKRtM+uW8l0HN8gwUqVGKGncaTmAzbdI2Gm3sFYI1zcMSFamDp9S8St
G+HBoQl/hdq0GMNlXG4pkwuMJKdtp5UEkBPrFjd9KY81DJaK81wldecUVLXXC2zL
N4569D7xKe7fzxTrTuVA0FwNesUaarHSO8auT3JwPRXPYHmqJjtDLGH7dMxePIPa
XVCN9pRhAoGBAOFxFahyjKzDFPnL7PXkz7KJdiowVjp0Hw5n0PjZGoLAi+AX0Q3s
VUtB3EW/z57twUmrgsHuXSGTG4bKvOlCL98j23DiNol2Wl9MSj9Ri/2uaAxMLTU0
2MqXIaUbfvwNy0uqaimHKFA7ZvQg9Q8xNrAy7iMHFtYkfpr/8BIA4o4vAoGBAOOJ
0aCCFU7RoZNmQmw/yXFAFLureG6CqgtFvSo4FAAkCEDAa+RN3MKW4ohqOMG+u9nx
mAbj1K0nxt0LPc5t5cjtv+IMFuL8xKq+LfKwODBspKQUhBTnbAKidiXvjSPUVZfL
EiLgKY6PxvNJ2QQjw1rn92dpgZR7cu14c+FTIOEZAoGBALjWRAChMq+vHvKT/Uu6
d4QValm62egBLzlbax2suyy6+7QXMuMsgt46OITDeFIA83oYchPZAGi3uVjxvqOt
DZzxREkwX7Ci5gO+hB2YGaQ7q7lxd5tpIdowwXgirCGymZ0HMxWraCUoHwhIQURc
gE9E4rS7akDXGSqybz4Dlb0nAoGBAKvEAUQ6jt1GMMP1wRS4flgIuN4HDk3WQ4lo
5uj1FlwY10YSPCBHiuw2POIf1aKkWminEU26NXVVfrCk6M5pdbpdh6mb2LcXe1st
X8BBuNkNWqgmeKLTJF1EyQ3QLWqrwsVo3dMIBzcAYH6N885FNRbt33zoT5KIMnUD
pe6l8z8ZAoGAaqPOd0rVgYzP9TBTUbipbsFoaIDt5Zk4nElTL3KWC3D7mwWUibL6
ZNwwQmZVSkMeRTLCUizJMOTRR9HGBOs4owHkM0sKJyIbt+ZU/MT1/i4KrtIy6hix
Dr7i7ZJs2w/x31U8NSEi9iWGItsnkTeaVTWa354ZuOgMXrQn0cXT7c8=
-----END RSA PRIVATE KEY-----`)

	return cert, key

	// template := x509.Certificate{
	// 	SerialNumber: big.NewInt(2019),
	// 	Subject: pkix.Name{
	// 		CommonName: "root",
	// 	},
	// 	NotBefore: time.Now().Add(-time.Hour),
	// 	NotAfter:  time.Now().Add(time.Hour),
	// 	KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	// 	ExtKeyUsage: []x509.ExtKeyUsage{
	// 		x509.ExtKeyUsageServerAuth,
	// 		x509.ExtKeyUsageClientAuth,
	// 	},
	// 	BasicConstraintsValid: true,
	// }

	// certPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	// require.NoError(t, err)

	// certBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, certPrivKey.Public(), caKey)
	// require.NoError(t, err)

	// cert := pem.EncodeToMemory(&pem.Block{
	// 	Type:  "CERTIFICATE",
	// 	Bytes: certBytes,
	// })
	// certKey := pem.EncodeToMemory(&pem.Block{
	// 	Type:  "RSA PRIVATE KEY",
	// 	Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	// })

	// fmt.Printf("Client:\n%s\n", cert)

	// return cert, certKey
}

func generateClientTLS(t *testing.T, caCert *x509.Certificate, clientCert, clientKey []byte) *tls.Config {
	t.Helper()

	keyPair, err := tls.X509KeyPair(clientCert, clientKey)
	require.NoError(t, err)

	certPool := x509.NewCertPool()
	certPool.AddCert(caCert)

	return &tls.Config{
		RootCAs:      certPool,
		Certificates: []tls.Certificate{keyPair},
		ServerName:   "localhost",
	}
}
