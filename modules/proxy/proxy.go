package proxy

import "net/http"

// ProxyConfig holds proxy settings.
type ProxyConfig struct {
	Address  string
	Enabled  bool
}

func NewProxyConfig(address string, enabled bool) *ProxyConfig {
	return &ProxyConfig{Address: address, Enabled: enabled}
}

func (p *ProxyConfig) ConfigureTransport(tr *http.Transport) {
	// TODO: Implement proxy configuration for HTTP transport
}
