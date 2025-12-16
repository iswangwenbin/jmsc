package types

// ProxyType 代理类型
type ProxyType string

const (
	TypeSS        ProxyType = "ss"
	TypeSSR       ProxyType = "ssr"
	TypeVMess     ProxyType = "vmess"
	TypeVLESS     ProxyType = "vless"
	TypeTrojan    ProxyType = "trojan"
	TypeHysteria  ProxyType = "hysteria"
	TypeHysteria2 ProxyType = "hysteria2"
	TypeTUIC      ProxyType = "tuic"
	TypeWireGuard ProxyType = "wireguard"
	TypeHTTP      ProxyType = "http"
	TypeSOCKS5    ProxyType = "socks5"
)

// NetworkType 网络传输类型
type NetworkType string

const (
	NetworkTCP  NetworkType = "tcp"
	NetworkWS   NetworkType = "ws"
	NetworkH2   NetworkType = "h2"
	NetworkGRPC NetworkType = "grpc"
	NetworkHTTP NetworkType = "http"
)

// Proxy 统一代理节点结构
type Proxy struct {
	Name   string    `yaml:"name" json:"name"`
	Type   ProxyType `yaml:"type" json:"type"`
	Server string    `yaml:"server" json:"server"`
	Port   int       `yaml:"port" json:"port"`

	// 通用认证字段
	UUID     string `yaml:"uuid,omitempty" json:"uuid,omitempty"`
	Password string `yaml:"password,omitempty" json:"password,omitempty"`
	Username string `yaml:"username,omitempty" json:"username,omitempty"`

	// SS/SSR 特有
	Cipher        string `yaml:"cipher,omitempty" json:"cipher,omitempty"`
	Plugin        string `yaml:"plugin,omitempty" json:"plugin,omitempty"`
	PluginOpts    any    `yaml:"plugin-opts,omitempty" json:"plugin-opts,omitempty"`
	Obfs          string `yaml:"obfs,omitempty" json:"obfs,omitempty"`
	ObfsParam     string `yaml:"obfs-param,omitempty" json:"obfs-param,omitempty"`
	Protocol      string `yaml:"protocol,omitempty" json:"protocol,omitempty"`
	ProtocolParam string `yaml:"protocol-param,omitempty" json:"protocol-param,omitempty"`

	// VMess 特有
	AlterID int `yaml:"alterId,omitempty" json:"alterId,omitempty"`

	// VLESS 特有
	Flow string `yaml:"flow,omitempty" json:"flow,omitempty"`

	// TLS 相关
	TLS            bool     `yaml:"tls,omitempty" json:"tls,omitempty"`
	SkipCertVerify bool     `yaml:"skip-cert-verify,omitempty" json:"skip-cert-verify,omitempty"`
	ServerName     string   `yaml:"servername,omitempty" json:"servername,omitempty"`
	SNI            string   `yaml:"sni,omitempty" json:"sni,omitempty"`
	ALPN           []string `yaml:"alpn,omitempty" json:"alpn,omitempty"`
	Fingerprint    string   `yaml:"fingerprint,omitempty" json:"fingerprint,omitempty"`
	ClientFP       string   `yaml:"client-fingerprint,omitempty" json:"client-fingerprint,omitempty"`

	// 网络传输
	Network  NetworkType `yaml:"network,omitempty" json:"network,omitempty"`
	WSOpts   *WSOpts     `yaml:"ws-opts,omitempty" json:"ws-opts,omitempty"`
	HTTPOpts *HTTPOpts   `yaml:"http-opts,omitempty" json:"http-opts,omitempty"`
	H2Opts   *H2Opts     `yaml:"h2-opts,omitempty" json:"h2-opts,omitempty"`
	GRPCOpts *GRPCOpts   `yaml:"grpc-opts,omitempty" json:"grpc-opts,omitempty"`

	// Reality
	RealityOpts *RealityOpts `yaml:"reality-opts,omitempty" json:"reality-opts,omitempty"`

	// Hysteria/Hysteria2 特有
	ObfsPassword string `yaml:"obfs-password,omitempty" json:"obfs-password,omitempty"`
	AuthStr      string `yaml:"auth-str,omitempty" json:"auth-str,omitempty"`
	Up           string `yaml:"up,omitempty" json:"up,omitempty"`
	Down         string `yaml:"down,omitempty" json:"down,omitempty"`
	Ports        string `yaml:"ports,omitempty" json:"ports,omitempty"`

	// TUIC 特有
	CongestionController string `yaml:"congestion-controller,omitempty" json:"congestion-controller,omitempty"`
	UDPRelayMode         string `yaml:"udp-relay-mode,omitempty" json:"udp-relay-mode,omitempty"`
	ReduceRTT            bool   `yaml:"reduce-rtt,omitempty" json:"reduce-rtt,omitempty"`

	// WireGuard 特有
	PrivateKey   string   `yaml:"private-key,omitempty" json:"private-key,omitempty"`
	PublicKey    string   `yaml:"public-key,omitempty" json:"public-key,omitempty"`
	PreSharedKey string   `yaml:"pre-shared-key,omitempty" json:"pre-shared-key,omitempty"`
	Reserved     []int    `yaml:"reserved,omitempty" json:"reserved,omitempty"`
	IP           string   `yaml:"ip,omitempty" json:"ip,omitempty"`
	IPv6         string   `yaml:"ipv6,omitempty" json:"ipv6,omitempty"`
	DNS          []string `yaml:"dns,omitempty" json:"dns,omitempty"`
	MTU          int      `yaml:"mtu,omitempty" json:"mtu,omitempty"`
	AllowedIPs   []string `yaml:"allowed-ips,omitempty" json:"allowed-ips,omitempty"`

	// 其他
	UDP            bool `yaml:"udp,omitempty" json:"udp,omitempty"`
	TFO            bool `yaml:"tfo,omitempty" json:"tfo,omitempty"`
	UDPOverTCP     bool `yaml:"udp-over-tcp,omitempty" json:"udp-over-tcp,omitempty"`
	FastOpen       bool `yaml:"fast-open,omitempty" json:"fast-open,omitempty"`
	RemoteDNS      bool `yaml:"remote-dns-resolve,omitempty" json:"remote-dns-resolve,omitempty"`
	HeartbeatIntvl int  `yaml:"heartbeat-interval,omitempty" json:"heartbeat-interval,omitempty"`
}

// WSOpts WebSocket 选项
type WSOpts struct {
	Path                string            `yaml:"path,omitempty" json:"path,omitempty"`
	Headers             map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	MaxEarlyData        int               `yaml:"max-early-data,omitempty" json:"max-early-data,omitempty"`
	EarlyDataHeaderName string            `yaml:"early-data-header-name,omitempty" json:"early-data-header-name,omitempty"`
	V2rayHTTPUpgrade    bool              `yaml:"v2ray-http-upgrade,omitempty" json:"v2ray-http-upgrade,omitempty"`
}

// HTTPOpts HTTP 选项
type HTTPOpts struct {
	Path    string            `yaml:"path,omitempty" json:"path,omitempty"`
	Headers map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
}

// H2Opts HTTP/2 选项
type H2Opts struct {
	Path    string            `yaml:"path,omitempty" json:"path,omitempty"`
	Headers map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	Host    []string          `yaml:"host,omitempty" json:"host,omitempty"`
}

// GRPCOpts gRPC 选项
type GRPCOpts struct {
	GRPCServiceName string `yaml:"grpc-service-name,omitempty" json:"grpc-service-name,omitempty"`
}

// RealityOpts Reality 选项
type RealityOpts struct {
	PublicKey string `yaml:"public-key,omitempty" json:"public-key,omitempty"`
	ShortID   string `yaml:"short-id,omitempty" json:"short-id,omitempty"`
	SpiderX   string `yaml:"spider-x,omitempty" json:"spider-x,omitempty"`
}

// ClashConfig Clash 配置结构
type ClashConfig struct {
	Proxies []Proxy `yaml:"proxies" json:"proxies"`
}

// ConvertResult 转换结果
type ConvertResult struct {
	Success bool   `json:"success"`
	Data    string `json:"data"`
	Count   int    `json:"count"`
}
