package parser

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"jmsc/pkg/types"
)

// ParseClashYAML 解析 Clash YAML 配置文件
func ParseClashYAML(content string) ([]*types.Proxy, error) {
	// 只清理真正有问题的控制字符，保留 \t \n \r
	re := regexp.MustCompile(`[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]`)
	content = re.ReplaceAllString(content, "")

	// 尝试解析 YAML
	var config map[string]any
	if err := yaml.Unmarshal([]byte(content), &config); err != nil {
		// 尝试解析为数组
		var arr []map[string]any
		if err2 := yaml.Unmarshal([]byte(content), &arr); err2 != nil {
			return nil, err
		}
		return parseProxyMaps(arr)
	}

	// 查找代理节点
	var proxies []map[string]any

	// 支持多种写法
	candidates := []any{
		config["proxies"],
		config["Proxy"],
		config["payload"],
	}

	// proxy-providers 嵌套
	if pp, ok := config["proxy-providers"].(map[string]any); ok {
		for _, v := range pp {
			if provider, ok := v.(map[string]any); ok {
				if ps, ok := provider["proxies"].([]any); ok {
					for _, p := range ps {
						if pm, ok := p.(map[string]any); ok {
							proxies = append(proxies, pm)
						}
					}
				}
				if payload, ok := provider["payload"].([]any); ok {
					for _, p := range payload {
						if pm, ok := p.(map[string]any); ok {
							proxies = append(proxies, pm)
						}
					}
				}
			}
		}
	}

	for _, candidate := range candidates {
		if arr, ok := candidate.([]any); ok {
			for _, item := range arr {
				if pm, ok := item.(map[string]any); ok {
					proxies = append(proxies, pm)
				}
			}
		}
	}

	// 去重
	seen := make(map[string]bool)
	var unique []map[string]any
	for _, p := range proxies {
		name, _ := p["name"].(string)
		server, _ := p["server"].(string)
		port := getInt(p, "port")
		key := name + "|" + server + "|" + string(rune(port))
		if !seen[key] {
			seen[key] = true
			unique = append(unique, p)
		}
	}

	return parseProxyMaps(unique)
}

// parseProxyMaps 将 map 数组转换为 Proxy 数组
func parseProxyMaps(maps []map[string]any) ([]*types.Proxy, error) {
	var proxies []*types.Proxy
	for _, m := range maps {
		proxy := mapToProxy(m)
		if proxy != nil {
			proxies = append(proxies, proxy)
		}
	}
	return proxies, nil
}

// mapToProxy 将 map 转换为 Proxy
func mapToProxy(m map[string]any) *types.Proxy {
	proxyType := getString(m, "type")
	if proxyType == "" {
		return nil
	}

	proxy := &types.Proxy{
		Name:   getString(m, "name"),
		Type:   types.ProxyType(proxyType),
		Server: getString(m, "server"),
		Port:   getInt(m, "port"),
	}

	// 通用字段
	proxy.UUID = getString(m, "uuid")
	proxy.Password = getString(m, "password")
	proxy.Username = getString(m, "username")
	proxy.Cipher = getString(m, "cipher")
	proxy.TLS = getBool(m, "tls")
	proxy.SkipCertVerify = getBool(m, "skip-cert-verify")
	proxy.ServerName = getString(m, "servername")
	proxy.SNI = getString(m, "sni")
	proxy.Fingerprint = getString(m, "fingerprint")
	proxy.ClientFP = getString(m, "client-fingerprint")
	proxy.UDP = getBool(m, "udp")

	// ALPN
	if alpn, ok := m["alpn"].([]any); ok {
		for _, a := range alpn {
			if s, ok := a.(string); ok {
				proxy.ALPN = append(proxy.ALPN, s)
			}
		}
	}

	// 网络类型
	if network := getString(m, "network"); network != "" {
		proxy.Network = types.NetworkType(network)
	}

	// 根据类型解析特定字段
	switch proxy.Type {
	case types.TypeSS:
		parseSSFromMap(proxy, m)
	case types.TypeSSR:
		parseSSRFromMap(proxy, m)
	case types.TypeVMess:
		parseVMessFromMap(proxy, m)
	case types.TypeVLESS:
		parseVLESSFromMap(proxy, m)
	case types.TypeTrojan:
		parseTrojanFromMap(proxy, m)
	case types.TypeHysteria:
		parseHysteriaFromMap(proxy, m)
	case types.TypeHysteria2:
		parseHysteria2FromMap(proxy, m)
	case types.TypeTUIC:
		parseTUICFromMap(proxy, m)
	case types.TypeWireGuard:
		parseWireGuardFromMap(proxy, m)
	}

	// 解析网络选项
	parseNetworkOpts(proxy, m)

	return proxy
}

func parseSSFromMap(proxy *types.Proxy, m map[string]any) {
	proxy.Plugin = getString(m, "plugin")
	proxy.PluginOpts = m["plugin-opts"]
	proxy.UDPOverTCP = getBool(m, "udp-over-tcp")
}

func parseSSRFromMap(proxy *types.Proxy, m map[string]any) {
	proxy.Protocol = getString(m, "protocol")
	proxy.ProtocolParam = getString(m, "protocol-param")
	proxy.Obfs = getString(m, "obfs")
	proxy.ObfsParam = getString(m, "obfs-param")
}

func parseVMessFromMap(proxy *types.Proxy, m map[string]any) {
	proxy.AlterID = getInt(m, "alterId")
}

func parseVLESSFromMap(proxy *types.Proxy, m map[string]any) {
	proxy.Flow = getString(m, "flow")

	// Reality
	if ro, ok := m["reality-opts"].(map[string]any); ok {
		proxy.RealityOpts = &types.RealityOpts{
			PublicKey: getString(ro, "public-key"),
			ShortID:   getString(ro, "short-id"),
			SpiderX:   getString(ro, "spider-x"),
		}
	}
}

func parseTrojanFromMap(proxy *types.Proxy, m map[string]any) {
	// 大部分字段已在通用解析中处理
}

func parseHysteriaFromMap(proxy *types.Proxy, m map[string]any) {
	proxy.AuthStr = getString(m, "auth-str")
	proxy.Protocol = getString(m, "protocol")
	proxy.Up = getString(m, "up")
	proxy.Down = getString(m, "down")
	proxy.Obfs = getString(m, "obfs")
	proxy.Ports = getString(m, "ports")
	proxy.FastOpen = getBool(m, "fast-open")
}

func parseHysteria2FromMap(proxy *types.Proxy, m map[string]any) {
	proxy.Obfs = getString(m, "obfs")
	proxy.ObfsPassword = getString(m, "obfs-password")
}

func parseTUICFromMap(proxy *types.Proxy, m map[string]any) {
	proxy.CongestionController = getString(m, "congestion-controller")
	proxy.UDPRelayMode = getString(m, "udp-relay-mode")
	proxy.ReduceRTT = getBool(m, "reduce-rtt")
}

func parseWireGuardFromMap(proxy *types.Proxy, m map[string]any) {
	proxy.PrivateKey = getString(m, "private-key")
	proxy.PublicKey = getString(m, "public-key")
	proxy.PreSharedKey = getString(m, "pre-shared-key")
	proxy.IP = getString(m, "ip")
	proxy.IPv6 = getString(m, "ipv6")
	proxy.MTU = getInt(m, "mtu")
	proxy.RemoteDNS = getBool(m, "remote-dns-resolve")

	// Reserved
	if reserved, ok := m["reserved"].([]any); ok {
		for _, r := range reserved {
			if v, ok := r.(int); ok {
				proxy.Reserved = append(proxy.Reserved, v)
			} else if v, ok := r.(float64); ok {
				proxy.Reserved = append(proxy.Reserved, int(v))
			}
		}
	}

	// DNS
	if dns, ok := m["dns"].([]any); ok {
		for _, d := range dns {
			if s, ok := d.(string); ok {
				proxy.DNS = append(proxy.DNS, s)
			}
		}
	}

	// Allowed IPs
	if ips, ok := m["allowed-ips"].([]any); ok {
		for _, ip := range ips {
			if s, ok := ip.(string); ok {
				proxy.AllowedIPs = append(proxy.AllowedIPs, s)
			}
		}
	}
}

func parseNetworkOpts(proxy *types.Proxy, m map[string]any) {
	// WebSocket
	if wsOpts, ok := m["ws-opts"].(map[string]any); ok {
		proxy.WSOpts = &types.WSOpts{
			Path:             getString(wsOpts, "path"),
			V2rayHTTPUpgrade: getBool(wsOpts, "v2ray-http-upgrade"),
		}
		if headers, ok := wsOpts["headers"].(map[string]any); ok {
			proxy.WSOpts.Headers = make(map[string]string)
			for k, v := range headers {
				if s, ok := v.(string); ok {
					proxy.WSOpts.Headers[k] = s
				}
			}
		}
	}

	// HTTP
	if httpOpts, ok := m["http-opts"].(map[string]any); ok {
		proxy.HTTPOpts = &types.HTTPOpts{
			Path: getString(httpOpts, "path"),
		}
		if headers, ok := httpOpts["headers"].(map[string]any); ok {
			proxy.HTTPOpts.Headers = make(map[string]string)
			for k, v := range headers {
				if s, ok := v.(string); ok {
					proxy.HTTPOpts.Headers[k] = s
				}
			}
		}
	}

	// H2
	if h2Opts, ok := m["h2-opts"].(map[string]any); ok {
		proxy.H2Opts = &types.H2Opts{
			Path: getString(h2Opts, "path"),
		}
		if host, ok := h2Opts["host"].([]any); ok {
			for _, h := range host {
				if s, ok := h.(string); ok {
					proxy.H2Opts.Host = append(proxy.H2Opts.Host, s)
				}
			}
		}
	}

	// gRPC
	if grpcOpts, ok := m["grpc-opts"].(map[string]any); ok {
		proxy.GRPCOpts = &types.GRPCOpts{
			GRPCServiceName: getString(grpcOpts, "grpc-service-name"),
		}
	}
}

// 辅助函数
func getString(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

func getInt(m map[string]any, key string) int {
	if v, ok := m[key]; ok {
		switch val := v.(type) {
		case int:
			return val
		case float64:
			return int(val)
		case string:
			// 尝试解析
			var i int
			if _, err := fmt.Sscanf(val, "%d", &i); err == nil {
				return i
			}
		}
	}
	return 0
}

func getBool(m map[string]any, key string) bool {
	if v, ok := m[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}
