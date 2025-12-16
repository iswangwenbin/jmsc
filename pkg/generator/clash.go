package generator

import (
	_ "embed"
	"strings"

	"gopkg.in/yaml.v3"

	"jmsc/pkg/types"
	"jmsc/pkg/utils"
)

//go:embed clash_template.yaml
var clashTemplate []byte

// ClashOutputMode 输出模式
type ClashOutputMode string

const (
	ModeProxies ClashOutputMode = "proxies"
	ModePayload ClashOutputMode = "payload"
	ModeNone    ClashOutputMode = "none"
)

// GenerateClash 生成 Clash 配置
func GenerateClash(proxies []*types.Proxy, mode ClashOutputMode) (string, error) {
	if len(proxies) == 0 {
		return "# 无有效节点\n# No valid nodes", nil
	}

	// 转换为 Clash 格式的 map
	var clashProxies []map[string]any
	var proxyNames []string
	for _, proxy := range proxies {
		node := proxyToClashMap(proxy)
		if node != nil {
			clashProxies = append(clashProxies, node)
			proxyNames = append(proxyNames, proxy.Name)
		}
	}

	// 根据模式生成输出
	var output any
	switch mode {
	case ModeProxies:
		// 使用模板生成完整配置
		output = buildFromTemplate(clashProxies, proxyNames)
	case ModePayload:
		output = map[string]any{"payload": clashProxies}
	case ModeNone:
		output = clashProxies
	default:
		output = buildFromTemplate(clashProxies, proxyNames)
	}

	// 生成 YAML
	data, err := yaml.Marshal(output)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// buildFromTemplate 从模板构建完整配置
func buildFromTemplate(clashProxies []map[string]any, proxyNames []string) map[string]any {
	// 解析模板
	var config map[string]any
	if err := yaml.Unmarshal(clashTemplate, &config); err != nil {
		// 模板解析失败，使用默认配置
		config = make(map[string]any)
	}

	// 注入 proxies
	config["proxies"] = clashProxies

	// 注入 proxy-groups 中的 proxies 列表
	if groups, ok := config["proxy-groups"].([]any); ok {
		for _, g := range groups {
			if group, ok := g.(map[string]any); ok {
				group["proxies"] = proxyNames
			}
		}
	}

	return config
}

// GenerateClashNode 生成单个节点的 YAML
func GenerateClashNode(proxy *types.Proxy) (string, error) {
	node := proxyToClashMap(proxy)
	if node == nil {
		return "", nil
	}

	data, err := yaml.Marshal(node)
	if err != nil {
		return "", err
	}

	// 添加 - 前缀
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var result []string
	for i, line := range lines {
		if i == 0 {
			result = append(result, "- "+line)
		} else {
			result = append(result, "  "+line)
		}
	}

	return strings.Join(result, "\n"), nil
}

// proxyToClashMap 将 Proxy 转换为 Clash 格式的 map
func proxyToClashMap(proxy *types.Proxy) map[string]any {
	if proxy == nil {
		return nil
	}

	node := make(map[string]any)

	// 基础字段
	node["name"] = proxy.Name
	node["type"] = string(proxy.Type)
	node["server"] = utils.PunycodeDomain(proxy.Server)
	node["port"] = proxy.Port

	// 根据类型添加特定字段
	switch proxy.Type {
	case types.TypeSS:
		addSSFields(node, proxy)
	case types.TypeSSR:
		addSSRFields(node, proxy)
	case types.TypeVMess:
		addVMessFields(node, proxy)
	case types.TypeVLESS:
		addVLESSFields(node, proxy)
	case types.TypeTrojan:
		addTrojanFields(node, proxy)
	case types.TypeHysteria:
		addHysteriaFields(node, proxy)
	case types.TypeHysteria2:
		addHysteria2Fields(node, proxy)
	case types.TypeTUIC:
		addTUICFields(node, proxy)
	case types.TypeWireGuard:
		addWireGuardFields(node, proxy)
	case types.TypeHTTP:
		addHTTPFields(node, proxy)
	case types.TypeSOCKS5:
		addSOCKS5Fields(node, proxy)
	}

	// 清理空值
	cleanEmptyValues(node)

	return node
}

func addSSFields(node map[string]any, proxy *types.Proxy) {
	node["cipher"] = proxy.Cipher
	node["password"] = proxy.Password
	if proxy.Plugin != "" {
		node["plugin"] = proxy.Plugin
		if proxy.PluginOpts != nil {
			node["plugin-opts"] = proxy.PluginOpts
		}
	}
	if proxy.UDP {
		node["udp"] = true
	}
	if proxy.UDPOverTCP {
		node["udp-over-tcp"] = true
	}
}

func addSSRFields(node map[string]any, proxy *types.Proxy) {
	node["cipher"] = proxy.Cipher
	node["password"] = proxy.Password
	node["protocol"] = proxy.Protocol
	node["obfs"] = proxy.Obfs
	if proxy.ProtocolParam != "" {
		node["protocol-param"] = proxy.ProtocolParam
	}
	if proxy.ObfsParam != "" {
		node["obfs-param"] = proxy.ObfsParam
	}
}

func addVMessFields(node map[string]any, proxy *types.Proxy) {
	node["uuid"] = proxy.UUID
	node["alterId"] = proxy.AlterID
	node["cipher"] = utils.GetIfNotEmpty(proxy.Cipher, "auto")

	if proxy.TLS {
		node["tls"] = true
	}
	if proxy.ServerName != "" {
		node["servername"] = proxy.ServerName
	}
	if proxy.SkipCertVerify {
		node["skip-cert-verify"] = true
	}

	addNetworkOpts(node, proxy)
}

func addVLESSFields(node map[string]any, proxy *types.Proxy) {
	node["uuid"] = proxy.UUID

	if proxy.Flow != "" {
		node["flow"] = proxy.Flow
	}
	if proxy.TLS {
		node["tls"] = true
	}
	if proxy.ServerName != "" {
		node["servername"] = proxy.ServerName
	}
	if proxy.SkipCertVerify {
		node["skip-cert-verify"] = true
	}
	if proxy.ClientFP != "" {
		node["client-fingerprint"] = proxy.ClientFP
	}
	if len(proxy.ALPN) > 0 {
		node["alpn"] = proxy.ALPN
	}

	// Reality
	if proxy.RealityOpts != nil {
		realityOpts := make(map[string]any)
		if proxy.RealityOpts.PublicKey != "" {
			realityOpts["public-key"] = proxy.RealityOpts.PublicKey
		}
		if proxy.RealityOpts.ShortID != "" {
			realityOpts["short-id"] = proxy.RealityOpts.ShortID
		}
		if proxy.RealityOpts.SpiderX != "" {
			realityOpts["spider-x"] = proxy.RealityOpts.SpiderX
		}
		if len(realityOpts) > 0 {
			node["reality-opts"] = realityOpts
		}
	}

	addNetworkOpts(node, proxy)
}

func addTrojanFields(node map[string]any, proxy *types.Proxy) {
	node["password"] = proxy.Password

	if proxy.SNI != "" {
		node["sni"] = proxy.SNI
	}
	if proxy.SkipCertVerify {
		node["skip-cert-verify"] = true
	}
	if len(proxy.ALPN) > 0 {
		node["alpn"] = proxy.ALPN
	}
	if proxy.Fingerprint != "" {
		node["fingerprint"] = proxy.Fingerprint
	}

	addNetworkOpts(node, proxy)
}

func addHysteriaFields(node map[string]any, proxy *types.Proxy) {
	if proxy.AuthStr != "" {
		node["auth-str"] = proxy.AuthStr
	}
	if proxy.Protocol != "" {
		node["protocol"] = proxy.Protocol
	}
	if proxy.Up != "" {
		node["up"] = proxy.Up
	}
	if proxy.Down != "" {
		node["down"] = proxy.Down
	}
	if proxy.Obfs != "" {
		node["obfs"] = proxy.Obfs
	}
	if proxy.SNI != "" {
		node["sni"] = proxy.SNI
	}
	if proxy.SkipCertVerify {
		node["skip-cert-verify"] = true
	}
	if len(proxy.ALPN) > 0 {
		node["alpn"] = proxy.ALPN
	}
	if proxy.Ports != "" {
		node["ports"] = proxy.Ports
	}
	if proxy.FastOpen {
		node["fast-open"] = true
	}
}

func addHysteria2Fields(node map[string]any, proxy *types.Proxy) {
	node["password"] = proxy.Password

	if proxy.Obfs != "" {
		node["obfs"] = proxy.Obfs
	}
	if proxy.ObfsPassword != "" {
		node["obfs-password"] = proxy.ObfsPassword
	}
	if proxy.SNI != "" {
		node["sni"] = proxy.SNI
	}
	if proxy.SkipCertVerify {
		node["skip-cert-verify"] = true
	}
	if len(proxy.ALPN) > 0 {
		node["alpn"] = proxy.ALPN
	}
	if proxy.Fingerprint != "" {
		node["fingerprint"] = proxy.Fingerprint
	}
}

func addTUICFields(node map[string]any, proxy *types.Proxy) {
	node["uuid"] = proxy.UUID
	node["password"] = proxy.Password

	if proxy.SNI != "" {
		node["sni"] = proxy.SNI
	}
	if len(proxy.ALPN) > 0 {
		node["alpn"] = proxy.ALPN
	}
	if proxy.CongestionController != "" {
		node["congestion-controller"] = proxy.CongestionController
	}
	if proxy.UDPRelayMode != "" {
		node["udp-relay-mode"] = proxy.UDPRelayMode
	}
	if proxy.ReduceRTT {
		node["reduce-rtt"] = true
	}
	if proxy.SkipCertVerify {
		node["skip-cert-verify"] = true
	}
}

func addWireGuardFields(node map[string]any, proxy *types.Proxy) {
	node["private-key"] = proxy.PrivateKey

	if proxy.PublicKey != "" {
		node["public-key"] = proxy.PublicKey
	}
	if proxy.PreSharedKey != "" {
		node["pre-shared-key"] = proxy.PreSharedKey
	}
	if proxy.IP != "" {
		node["ip"] = proxy.IP
	}
	if proxy.IPv6 != "" {
		node["ipv6"] = proxy.IPv6
	}
	if len(proxy.Reserved) > 0 {
		node["reserved"] = proxy.Reserved
	}
	if len(proxy.AllowedIPs) > 0 {
		node["allowed-ips"] = proxy.AllowedIPs
	}
	if proxy.MTU > 0 {
		node["mtu"] = proxy.MTU
	}
	if len(proxy.DNS) > 0 {
		node["dns"] = proxy.DNS
	}
	if proxy.UDP {
		node["udp"] = true
	}
	if proxy.RemoteDNS {
		node["remote-dns-resolve"] = true
	}
}

func addHTTPFields(node map[string]any, proxy *types.Proxy) {
	if proxy.Username != "" {
		node["username"] = proxy.Username
	}
	if proxy.Password != "" {
		node["password"] = proxy.Password
	}
	if proxy.TLS {
		node["tls"] = true
	}
	if proxy.SkipCertVerify {
		node["skip-cert-verify"] = true
	}
	if proxy.Fingerprint != "" {
		node["fingerprint"] = proxy.Fingerprint
	}
}

func addSOCKS5Fields(node map[string]any, proxy *types.Proxy) {
	if proxy.Username != "" {
		node["username"] = proxy.Username
	}
	if proxy.Password != "" {
		node["password"] = proxy.Password
	}
	if proxy.TLS {
		node["tls"] = true
	}
	if proxy.SkipCertVerify {
		node["skip-cert-verify"] = true
	}
	if proxy.UDP {
		node["udp"] = true
	}
}

func addNetworkOpts(node map[string]any, proxy *types.Proxy) {
	if proxy.Network != "" && proxy.Network != types.NetworkTCP {
		node["network"] = string(proxy.Network)
	}

	if proxy.WSOpts != nil {
		wsOpts := make(map[string]any)
		if proxy.WSOpts.Path != "" {
			wsOpts["path"] = proxy.WSOpts.Path
		}
		if len(proxy.WSOpts.Headers) > 0 {
			wsOpts["headers"] = proxy.WSOpts.Headers
		}
		if proxy.WSOpts.V2rayHTTPUpgrade {
			wsOpts["v2ray-http-upgrade"] = true
		}
		if len(wsOpts) > 0 {
			node["ws-opts"] = wsOpts
		}
	}

	if proxy.HTTPOpts != nil {
		httpOpts := make(map[string]any)
		if proxy.HTTPOpts.Path != "" {
			httpOpts["path"] = proxy.HTTPOpts.Path
		}
		if len(proxy.HTTPOpts.Headers) > 0 {
			httpOpts["headers"] = proxy.HTTPOpts.Headers
		}
		if len(httpOpts) > 0 {
			node["http-opts"] = httpOpts
		}
	}

	if proxy.H2Opts != nil {
		h2Opts := make(map[string]any)
		if proxy.H2Opts.Path != "" {
			h2Opts["path"] = proxy.H2Opts.Path
		}
		if len(proxy.H2Opts.Host) > 0 {
			h2Opts["host"] = proxy.H2Opts.Host
		}
		if len(h2Opts) > 0 {
			node["h2-opts"] = h2Opts
		}
	}

	if proxy.GRPCOpts != nil {
		grpcOpts := make(map[string]any)
		if proxy.GRPCOpts.GRPCServiceName != "" {
			grpcOpts["grpc-service-name"] = proxy.GRPCOpts.GRPCServiceName
		}
		if len(grpcOpts) > 0 {
			node["grpc-opts"] = grpcOpts
		}
	}
}

// cleanEmptyValues 清理空值
func cleanEmptyValues(m map[string]any) {
	for k, v := range m {
		if v == nil {
			delete(m, k)
			continue
		}
		switch val := v.(type) {
		case string:
			if val == "" {
				delete(m, k)
			}
		case int:
			if val == 0 && k != "port" && k != "alterId" {
				delete(m, k)
			}
		case bool:
			if !val {
				delete(m, k)
			}
		case []string:
			if len(val) == 0 {
				delete(m, k)
			}
		case []int:
			if len(val) == 0 {
				delete(m, k)
			}
		case map[string]any:
			cleanEmptyValues(val)
			if len(val) == 0 {
				delete(m, k)
			}
		case map[string]string:
			if len(val) == 0 {
				delete(m, k)
			}
		}
	}
}
