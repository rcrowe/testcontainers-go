package cockroachdb

import (
	"context"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"path/filepath"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	certsDir = "/tmp"

	defaultSQLPort   = "26257"
	defaultAdminPort = "8080"

	defaultImage     = "cockroachdb/cockroach"
	defaultImageTag  = "latest-v23.1"
	defaultDatabase  = "defaultdb"
	defaultStoreSize = "100%"
)

// CockroachDBContainer represents the CockroachDB container type used in the module
type CockroachDBContainer struct {
	testcontainers.Container
	opts options
}

// MustConnectionString panics if the address cannot be determined.
func (c *CockroachDBContainer) MustConnectionString(ctx context.Context) string {
	addr, err := c.ConnectionString(ctx)
	if err != nil {
		panic(err)
	}
	return addr
}

// ConnectionString returns the dial address to open a new connection to CockroachDB.
func (c *CockroachDBContainer) ConnectionString(ctx context.Context) (string, error) {
	mappedport, err := c.MappedPort(ctx, defaultSQLPort+"/tcp")
	if err != nil {
		return "", err
	}

	hostIP, err := c.Host(ctx)
	if err != nil {
		return "", err
	}

	sslMode := "disable"
	if c.opts.TLSEnabled {
		sslMode = "verify-full"
	}
	params := url.Values{
		"sslmode": []string{sslMode},
	}

	u := url.URL{
		Scheme:   "postgres",
		User:     url.User("root"),
		Host:     net.JoinHostPort(hostIP, mappedport.Port()),
		Path:     c.opts.Database,
		RawQuery: params.Encode(),
	}

	return u.String(), nil
}

// RunContainer creates an instance of the CockroachDB container type
func RunContainer(ctx context.Context, opts ...testcontainers.ContainerCustomizer) (*CockroachDBContainer, error) {
	req := testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			ExposedPorts: []string{
				defaultSQLPort + "/tcp",
				defaultAdminPort + "/tcp",
			},
			WaitingFor: wait.ForHTTP("/health").WithPort(defaultAdminPort),
		},
	}

	// apply options
	o := defaultOptions()
	for _, opt := range opts {
		if apply, ok := opt.(Option); ok {
			apply(&o)
		}
		opt.Customize(&req)
	}

	req.Image = image(req, o)
	req.Cmd = cmd(o)

	container, err := testcontainers.GenericContainer(ctx, req)
	if err != nil {
		return nil, err
	}

	if o.TLSEnabled {
		addTLS(ctx, container, o)
	}

	// start
	if err := container.Start(ctx); err != nil {
		return nil, err
	}
	return &CockroachDBContainer{Container: container, opts: o}, nil
}

func image(req testcontainers.GenericContainerRequest, opts options) string {
	if req.Image != "" {
		return req.Image
	}
	return fmt.Sprintf("%s:%s", defaultImage, opts.ImageTag)
}

func cmd(opts options) []string {
	// + exec /cockroach/cockroach start
	//	--logtostderr=WARNING
	//	--certs-dir /cockroach/cockroach-certs
	//	--listen-addr=:26357
	//	--sql-addr=:26257
	//	--advertise-addr cockroachdb-1.cockroachdb.auth-customer.svc.cluster.local
	//	--http-addr 0.0.0.0
	//	--join cockroachdb-0.cockroachdb:26257,cockroachdb-0.cockroachdb:26357,cockroachdb-1.cockroachdb:26257,cockroachdb-1.cockroachdb:26357,cockroachdb-2.cockroachdb:26257,cockroachdb-2.cockroachdb:26357
	//	--cache 25%
	//	--max-sql-memory 25%

	cmd := []string{
		"start-single-node",
		"--store=type=mem,size=" + opts.StoreSize,
	}

	if opts.TLSEnabled {

		cmd = append(cmd, "--certs-dir="+certsDir)
	} else {
		cmd = append(cmd, "--insecure")
	}

	return cmd
}

func addTLS(ctx context.Context, container testcontainers.Container, opts options) error {
	clientCert := []byte(`
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
	clientKey := []byte(`
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

	caBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: opts.TLSCA.Raw,
	})
	files := map[string][]byte{
		"ca.crt":          caBytes,
		"node.crt":        opts.TLSCert,
		"node.key":        opts.TLSKey,
		"client.root.crt": clientCert,
		"client.root.key": clientKey,
	}
	for filename, contents := range files {
		if err := container.CopyToContainer(ctx, contents, filepath.Join(certsDir, filename), 0o600); err != nil {
			return err
		}
	}
	return nil
}
