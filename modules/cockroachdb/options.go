package cockroachdb

import (
	"crypto/x509"

	"github.com/testcontainers/testcontainers-go"
)

type options struct {
	Database  string
	ImageTag  string
	StoreSize string

	TLS *TLSConfig
}

func defaultOptions() options {
	return options{
		Database:  defaultDatabase,
		ImageTag:  defaultImageTag,
		StoreSize: defaultStoreSize,
	}
}

// Compiler check to ensure that Option implements the testcontainers.ContainerCustomizer interface.
var _ testcontainers.ContainerCustomizer = (*Option)(nil)

// Option is an option for the CockroachDB container.
type Option func(*options)

// Customize is a NOOP. It's defined to satisfy the testcontainers.ContainerCustomizer interface.
func (o Option) Customize(*testcontainers.GenericContainerRequest) {
	// NOOP to satisfy interface.
}

// WithDatabase sets the name of the database to use.
func WithDatabase(database string) Option {
	return func(o *options) {
		o.Database = database
	}
}

// WithStoreSize sets the amount of available in-memory storage.
// See https://www.cockroachlabs.com/docs/stable/cockroach-start#store
func WithStoreSize(size string) Option {
	return func(o *options) {
		o.StoreSize = size
	}
}

type TLSConfig struct {
	CACert     *x509.Certificate
	NodeCert   []byte
	NodeKey    []byte
	ClientCert []byte
	ClientKey  []byte
}

// WithTLS enables TLS on the CockroachDB container.
// Cert and key must be a valid PEM-encoded certificate and key.
func WithTLS(cfg TLSConfig) Option {
	return func(o *options) {
		o.TLS = &cfg
	}
}
