package parser

import (
	"regexp"
	"strings"

	"jmsc/pkg/types"
	"jmsc/pkg/utils"
)

// ParseVLESS 解析 VLESS 链接
// 格式: vless://uuid@server:port?params#name
func ParseVLESS(uri string) (*types.Proxy, error) {
	content := strings.TrimPrefix(uri, "vless://")

	// 正则解析
	re := regexp.MustCompile(`^(.*?)@(.*?):(\d+)\/?(\?(.*?))?(?:#(.*?))?$`)
	matches := re.FindStringSubmatch(content)

	// 如果匹配失败，尝试 Shadowrocket base64 格式
	if matches == nil {
		return parseShadowrocketVLESS(content)
	}

	uuid := utils.URLDecode(matches[1])
	server := matches[2]
	port := utils.ParseInt(matches[3], 443)
	query := matches[5]
	name := utils.URLDecode(matches[6])

	proxy := &types.Proxy{
		Type:   types.TypeVLESS,
		Name:   name,
		Server: server,
		Port:   port,
		UUID:   uuid,
	}

	// 解析参数
	params := utils.ParseQueryString(query)

	// TLS 处理
	if security, ok := params["security"]; ok && security != "none" {
		proxy.TLS = true
	}

	// SNI
	if sni, ok := params["sni"]; ok {
		proxy.ServerName = sni
	} else if peer, ok := params["peer"]; ok {
		proxy.ServerName = peer
	}

	// Flow (XTLS)
	if flow, ok := params["flow"]; ok && flow != "" {
		proxy.Flow = "xtls-rprx-vision"
	}

	// Fingerprint
	if fp, ok := params["fp"]; ok {
		proxy.ClientFP = fp
	}

	// ALPN
	if alpn, ok := params["alpn"]; ok && alpn != "" {
		proxy.ALPN = strings.Split(alpn, ",")
	}

	// Skip cert verify
	if allow, ok := params["allowinsecure"]; ok {
		proxy.SkipCertVerify = utils.ParseBool(allow)
	}

	// Reality 参数
	if params["security"] == "reality" {
		proxy.RealityOpts = &types.RealityOpts{}
		if pbk, ok := params["pbk"]; ok {
			proxy.RealityOpts.PublicKey = pbk
		}
		if sid, ok := params["sid"]; ok {
			proxy.RealityOpts.ShortID = sid
		}
		if spx, ok := params["spx"]; ok {
			proxy.RealityOpts.SpiderX = spx
		}
	}

	// 网络类型
	parseVLESSNetwork(proxy, params)

	// 设置默认名称
	if proxy.Name == "" {
		proxy.Name = proxy.Server
	}

	return proxy, nil
}

// parseVLESSNetwork 解析 VLESS 网络配置
func parseVLESSNetwork(proxy *types.Proxy, params map[string]string) {
	netType := params["type"]

	switch netType {
	case "ws", "websocket":
		proxy.Network = types.NetworkWS
		proxy.WSOpts = &types.WSOpts{}
		if path, ok := params["path"]; ok {
			proxy.WSOpts.Path = path
		}
		if host, ok := params["host"]; ok {
			proxy.WSOpts.Headers = map[string]string{"Host": host}
		}
		// HTTP Upgrade
		if params["headertype"] == "http" {
			proxy.WSOpts.V2rayHTTPUpgrade = true
		}

	case "h2":
		proxy.Network = types.NetworkH2
		proxy.H2Opts = &types.H2Opts{}
		if path, ok := params["path"]; ok {
			proxy.H2Opts.Path = path
		}
		if host, ok := params["host"]; ok {
			proxy.H2Opts.Host = []string{host}
		}

	case "grpc":
		proxy.Network = types.NetworkGRPC
		proxy.GRPCOpts = &types.GRPCOpts{}
		if path, ok := params["path"]; ok {
			proxy.GRPCOpts.GRPCServiceName = path
		}
		if sn, ok := params["servicename"]; ok {
			proxy.GRPCOpts.GRPCServiceName = sn
		}

	case "http":
		proxy.Network = types.NetworkHTTP
		proxy.HTTPOpts = &types.HTTPOpts{}
		if path, ok := params["path"]; ok {
			proxy.HTTPOpts.Path = path
		}
		if host, ok := params["host"]; ok {
			proxy.HTTPOpts.Headers = map[string]string{"Host": host}
		}

	default:
		proxy.Network = types.NetworkTCP
	}

	// 自动填充 servername
	if proxy.TLS && proxy.ServerName == "" {
		if proxy.WSOpts != nil && proxy.WSOpts.Headers != nil {
			if host, ok := proxy.WSOpts.Headers["Host"]; ok {
				proxy.ServerName = host
			}
		} else if proxy.HTTPOpts != nil && proxy.HTTPOpts.Headers != nil {
			if host, ok := proxy.HTTPOpts.Headers["Host"]; ok {
				proxy.ServerName = host
			}
		}
	}
}

// parseShadowrocketVLESS 解析 Shadowrocket 格式的 VLESS
func parseShadowrocketVLESS(content string) (*types.Proxy, error) {
	// 格式: BASE64?params#name
	re := regexp.MustCompile(`^([a-zA-Z0-9+/=]+)(\?.*?)?(#.*)?$`)
	matches := re.FindStringSubmatch(content)
	if matches == nil {
		return nil, ErrInvalidFormat
	}

	base64Part := matches[1]
	query := matches[2]
	nameHash := matches[3]

	decoded := utils.DecodeBase64(base64Part)
	if decoded == "" {
		return nil, ErrInvalidFormat
	}

	// 拼接完整 URI 并重新解析
	fullURI := decoded
	if query != "" {
		fullURI += query
	}
	if nameHash != "" {
		fullURI += nameHash
	}

	return ParseVLESS("vless://" + fullURI)
}
