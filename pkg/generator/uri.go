package generator

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"jmsc/pkg/types"
	"jmsc/pkg/utils"
)

// GenerateURI 根据代理配置生成分享链接
func GenerateURI(proxy *types.Proxy) string {
	if proxy == nil {
		return ""
	}

	switch proxy.Type {
	case types.TypeSS:
		return generateSSURI(proxy)
	case types.TypeSSR:
		return generateSSRURI(proxy)
	case types.TypeVMess:
		return generateVMessURI(proxy)
	case types.TypeVLESS:
		return generateVLESSURI(proxy)
	case types.TypeTrojan:
		return generateTrojanURI(proxy)
	case types.TypeHysteria2:
		return generateHysteria2URI(proxy)
	case types.TypeHysteria:
		return generateHysteriaURI(proxy)
	case types.TypeTUIC:
		return generateTUICURI(proxy)
	case types.TypeWireGuard:
		return generateWireGuardURI(proxy)
	case types.TypeHTTP:
		return generateHTTPURI(proxy)
	case types.TypeSOCKS5:
		return generateSOCKS5URI(proxy)
	default:
		return ""
	}
}

// GenerateURIs 批量生成分享链接
func GenerateURIs(proxies []*types.Proxy) []string {
	var uris []string
	for _, proxy := range proxies {
		if uri := GenerateURI(proxy); uri != "" {
			uris = append(uris, uri)
		}
	}
	return uris
}

func generateSSURI(proxy *types.Proxy) string {
	// ss://BASE64(method:password)@server:port#name
	auth := fmt.Sprintf("%s:%s", proxy.Cipher, proxy.Password)
	encoded := base64.StdEncoding.EncodeToString([]byte(auth))
	name := url.QueryEscape(proxy.Name)
	return fmt.Sprintf("ss://%s@%s:%d#%s", encoded, utils.PunycodeDomain(proxy.Server), proxy.Port, name)
}

func generateSSRURI(proxy *types.Proxy) string {
	// ssr://BASE64(server:port:protocol:method:obfs:BASE64(password)/?params)
	password := base64.StdEncoding.EncodeToString([]byte(proxy.Password))
	remarks := base64.StdEncoding.EncodeToString([]byte(proxy.Name))

	main := fmt.Sprintf("%s:%d:%s:%s:%s:%s",
		proxy.Server, proxy.Port, proxy.Protocol, proxy.Cipher, proxy.Obfs, password)

	var params []string
	params = append(params, "remarks="+remarks)
	if proxy.ProtocolParam != "" {
		params = append(params, "protoparam="+base64.StdEncoding.EncodeToString([]byte(proxy.ProtocolParam)))
	}
	if proxy.ObfsParam != "" {
		params = append(params, "obfsparam="+base64.StdEncoding.EncodeToString([]byte(proxy.ObfsParam)))
	}

	full := main + "/?" + strings.Join(params, "&")
	return "ssr://" + base64.StdEncoding.EncodeToString([]byte(full))
}

func generateVMessURI(proxy *types.Proxy) string {
	// vmess://BASE64(JSON)
	vmess := map[string]any{
		"v":    "2",
		"ps":   proxy.Name,
		"add":  utils.PunycodeDomain(proxy.Server),
		"port": proxy.Port,
		"id":   proxy.UUID,
		"aid":  proxy.AlterID,
		"scy":  utils.GetIfNotEmpty(proxy.Cipher, "auto"),
		"net":  "tcp",
		"type": "none",
		"host": "",
		"path": "",
		"tls":  "none",
		"sni":  "",
	}

	// 网络类型
	if proxy.Network != "" {
		vmess["net"] = string(proxy.Network)
	}

	// TLS
	if proxy.TLS {
		vmess["tls"] = "tls"
	}

	// SNI
	if proxy.ServerName != "" {
		vmess["sni"] = proxy.ServerName
	}

	// WebSocket
	if proxy.WSOpts != nil {
		if proxy.WSOpts.Path != "" {
			vmess["path"] = proxy.WSOpts.Path
		}
		if proxy.WSOpts.Headers != nil {
			if host, ok := proxy.WSOpts.Headers["Host"]; ok {
				vmess["host"] = host
			}
		}
	}

	// gRPC
	if proxy.GRPCOpts != nil && proxy.GRPCOpts.GRPCServiceName != "" {
		vmess["path"] = proxy.GRPCOpts.GRPCServiceName
	}

	// ALPN
	if len(proxy.ALPN) > 0 {
		vmess["alpn"] = strings.Join(proxy.ALPN, ",")
	}

	// Fingerprint
	if proxy.Fingerprint != "" {
		vmess["fp"] = proxy.Fingerprint
	} else if proxy.ClientFP != "" {
		vmess["fp"] = proxy.ClientFP
	}

	jsonData, _ := json.Marshal(vmess)
	encoded := base64.StdEncoding.EncodeToString(jsonData)
	return "vmess://" + encoded
}

func generateVLESSURI(proxy *types.Proxy) string {
	// vless://uuid@server:port?params#name
	params := url.Values{}
	params.Set("type", string(utils.GetIfNotEmpty(string(proxy.Network), "tcp")))
	params.Set("encryption", "none")

	// Flow
	if proxy.Flow != "" {
		params.Set("flow", proxy.Flow)
	}

	// TLS / Reality
	if proxy.TLS || proxy.RealityOpts != nil {
		if proxy.RealityOpts != nil {
			params.Set("security", "reality")
			if proxy.RealityOpts.PublicKey != "" {
				params.Set("pbk", proxy.RealityOpts.PublicKey)
			}
			if proxy.RealityOpts.ShortID != "" {
				params.Set("sid", proxy.RealityOpts.ShortID)
			}
			if proxy.RealityOpts.SpiderX != "" {
				params.Set("spx", proxy.RealityOpts.SpiderX)
			}
		} else {
			params.Set("security", "tls")
		}

		if proxy.ServerName != "" {
			params.Set("sni", proxy.ServerName)
		}
		if proxy.ClientFP != "" {
			params.Set("fp", proxy.ClientFP)
		}
		if proxy.SkipCertVerify {
			params.Set("allowInsecure", "1")
		}
		if len(proxy.ALPN) > 0 {
			params.Set("alpn", strings.Join(proxy.ALPN, ","))
		}
	}

	// WebSocket
	if proxy.WSOpts != nil {
		if proxy.WSOpts.Path != "" {
			params.Set("path", proxy.WSOpts.Path)
		}
		if proxy.WSOpts.Headers != nil {
			if host, ok := proxy.WSOpts.Headers["Host"]; ok {
				params.Set("host", host)
			}
		}
	}

	// gRPC
	if proxy.GRPCOpts != nil && proxy.GRPCOpts.GRPCServiceName != "" {
		params.Set("serviceName", proxy.GRPCOpts.GRPCServiceName)
	}

	name := url.QueryEscape(proxy.Name)
	return fmt.Sprintf("vless://%s@%s:%d?%s#%s",
		proxy.UUID, utils.PunycodeDomain(proxy.Server), proxy.Port, params.Encode(), name)
}

func generateTrojanURI(proxy *types.Proxy) string {
	// trojan://password@server:port?params#name
	params := url.Values{}

	if proxy.Network != "" && proxy.Network != types.NetworkTCP {
		params.Set("type", string(proxy.Network))
	}
	if proxy.SNI != "" {
		params.Set("sni", proxy.SNI)
	} else if proxy.ServerName != "" {
		params.Set("sni", proxy.ServerName)
	}
	if proxy.SkipCertVerify {
		params.Set("allowInsecure", "1")
	}
	if proxy.Fingerprint != "" {
		params.Set("fp", proxy.Fingerprint)
	}

	// WebSocket
	if proxy.WSOpts != nil {
		if proxy.WSOpts.Path != "" {
			params.Set("path", proxy.WSOpts.Path)
		}
		if proxy.WSOpts.Headers != nil {
			if host, ok := proxy.WSOpts.Headers["Host"]; ok {
				params.Set("host", host)
			}
		}
	}

	name := url.QueryEscape(proxy.Name)
	password := url.QueryEscape(proxy.Password)

	queryStr := params.Encode()
	if queryStr != "" {
		queryStr = "?" + queryStr
	}

	return fmt.Sprintf("trojan://%s@%s:%d%s#%s",
		password, utils.PunycodeDomain(proxy.Server), proxy.Port, queryStr, name)
}

func generateHysteria2URI(proxy *types.Proxy) string {
	// hysteria2://password@server:port?params#name
	params := url.Values{}

	if proxy.SNI != "" {
		params.Set("sni", proxy.SNI)
	}
	if proxy.Obfs != "" {
		params.Set("obfs", proxy.Obfs)
	}
	if proxy.ObfsPassword != "" {
		params.Set("obfs-password", proxy.ObfsPassword)
	}
	if proxy.SkipCertVerify {
		params.Set("insecure", "1")
	}
	if len(proxy.ALPN) > 0 {
		params.Set("alpn", strings.Join(proxy.ALPN, ","))
	}

	name := url.QueryEscape(proxy.Name)
	password := url.QueryEscape(proxy.Password)

	queryStr := params.Encode()
	if queryStr != "" {
		queryStr = "?" + queryStr
	}

	return fmt.Sprintf("hysteria2://%s@%s:%d%s#%s",
		password, utils.PunycodeDomain(proxy.Server), proxy.Port, queryStr, name)
}

func generateHysteriaURI(proxy *types.Proxy) string {
	// hysteria://server:port?params#name
	params := url.Values{}

	if proxy.AuthStr != "" {
		params.Set("auth", proxy.AuthStr)
	}
	if proxy.Protocol != "" {
		params.Set("protocol", proxy.Protocol)
	}
	if proxy.Up != "" {
		params.Set("upmbps", proxy.Up)
	}
	if proxy.Down != "" {
		params.Set("downmbps", proxy.Down)
	}
	if proxy.Obfs != "" {
		params.Set("obfs", proxy.Obfs)
	}
	if proxy.SNI != "" {
		params.Set("sni", proxy.SNI)
	}
	if proxy.SkipCertVerify {
		params.Set("insecure", "1")
	}
	if len(proxy.ALPN) > 0 {
		params.Set("alpn", strings.Join(proxy.ALPN, ","))
	}
	if proxy.Ports != "" {
		params.Set("mport", proxy.Ports)
	}

	name := url.QueryEscape(proxy.Name)

	queryStr := params.Encode()
	if queryStr != "" {
		queryStr = "?" + queryStr
	}

	return fmt.Sprintf("hysteria://%s:%d%s#%s",
		utils.PunycodeDomain(proxy.Server), proxy.Port, queryStr, name)
}

func generateTUICURI(proxy *types.Proxy) string {
	// tuic://uuid:password@server:port?params#name
	params := url.Values{}

	if proxy.SNI != "" {
		params.Set("sni", proxy.SNI)
	}
	if len(proxy.ALPN) > 0 {
		params.Set("alpn", strings.Join(proxy.ALPN, ","))
	}
	if proxy.CongestionController != "" {
		params.Set("congestion_controller", proxy.CongestionController)
	}
	if proxy.UDPRelayMode != "" {
		params.Set("udp_relay_mode", proxy.UDPRelayMode)
	}
	if proxy.SkipCertVerify {
		params.Set("allow_insecure", "1")
	}

	name := url.QueryEscape(proxy.Name)
	password := url.QueryEscape(proxy.Password)

	queryStr := params.Encode()
	if queryStr != "" {
		queryStr = "?" + queryStr
	}

	return fmt.Sprintf("tuic://%s:%s@%s:%d%s#%s",
		proxy.UUID, password, utils.PunycodeDomain(proxy.Server), proxy.Port, queryStr, name)
}

func generateWireGuardURI(proxy *types.Proxy) string {
	// wireguard://privatekey@server:port?params#name
	params := url.Values{}

	if proxy.PublicKey != "" {
		params.Set("publickey", proxy.PublicKey)
	}
	if proxy.IP != "" || proxy.IPv6 != "" {
		var addrs []string
		if proxy.IP != "" {
			addrs = append(addrs, proxy.IP)
		}
		if proxy.IPv6 != "" {
			addrs = append(addrs, proxy.IPv6)
		}
		params.Set("address", strings.Join(addrs, ","))
	}
	if len(proxy.Reserved) == 3 {
		params.Set("reserved", fmt.Sprintf("%d,%d,%d", proxy.Reserved[0], proxy.Reserved[1], proxy.Reserved[2]))
	}
	if proxy.MTU > 0 {
		params.Set("mtu", fmt.Sprintf("%d", proxy.MTU))
	}
	if len(proxy.DNS) > 0 {
		params.Set("dns", strings.Join(proxy.DNS, ","))
	}

	name := url.QueryEscape(proxy.Name)
	privateKey := url.QueryEscape(proxy.PrivateKey)

	queryStr := params.Encode()
	if queryStr != "" {
		queryStr = "?" + queryStr
	}

	return fmt.Sprintf("wireguard://%s@%s:%d%s#%s",
		privateKey, utils.PunycodeDomain(proxy.Server), proxy.Port, queryStr, name)
}

func generateHTTPURI(proxy *types.Proxy) string {
	// http://[user:pass@]server:port#name
	protocol := "http"
	if proxy.TLS {
		protocol = "https"
	}

	var auth string
	if proxy.Username != "" {
		auth = url.QueryEscape(proxy.Username)
		if proxy.Password != "" {
			auth += ":" + url.QueryEscape(proxy.Password)
		}
		auth += "@"
	}

	name := url.QueryEscape(proxy.Name)
	return fmt.Sprintf("%s://%s%s:%d#%s",
		protocol, auth, utils.PunycodeDomain(proxy.Server), proxy.Port, name)
}

func generateSOCKS5URI(proxy *types.Proxy) string {
	// socks5://[user:pass@]server:port#name
	var auth string
	if proxy.Username != "" {
		auth = url.QueryEscape(proxy.Username)
		if proxy.Password != "" {
			auth += ":" + url.QueryEscape(proxy.Password)
		}
		auth += "@"
	}

	name := url.QueryEscape(proxy.Name)
	return fmt.Sprintf("socks5://%s%s:%d#%s",
		auth, utils.PunycodeDomain(proxy.Server), proxy.Port, name)
}
