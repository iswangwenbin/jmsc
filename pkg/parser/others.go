package parser

import (
	"regexp"
	"strconv"
	"strings"

	"jmsc/pkg/types"
	"jmsc/pkg/utils"
)

// ParseTUIC 解析 TUIC 链接
// 格式: tuic://uuid:password@server:port?params#name
func ParseTUIC(uri string) (*types.Proxy, error) {
	content := strings.TrimPrefix(uri, "tuic://")

	// 正则解析
	re := regexp.MustCompile(`^(.*?):(.*?)@(.*?)(:(\d+))?\/?(\?(.*?))?(?:#(.*?))?$`)
	matches := re.FindStringSubmatch(content)
	if matches == nil {
		return nil, ErrInvalidFormat
	}

	uuid := matches[1]
	password := utils.URLDecode(matches[2])
	server := matches[3]
	port := utils.ParseInt(matches[5], 443)
	query := matches[7]
	name := utils.URLDecode(matches[8])

	proxy := &types.Proxy{
		Type:     types.TypeTUIC,
		Name:     utils.GetIfNotEmpty(name, "TUIC Node"),
		Server:   server,
		Port:     port,
		UUID:     uuid,
		Password: password,
	}

	// 解析参数
	params := utils.ParseQueryString(query)

	// ALPN
	if alpn, ok := params["alpn"]; ok && alpn != "" {
		proxy.ALPN = strings.Split(alpn, ",")
	}

	// SNI
	if sni, ok := params["sni"]; ok {
		proxy.SNI = sni
	}

	// congestion controller
	if cc, ok := params["congestion-controller"]; ok {
		proxy.CongestionController = cc
	}
	if cc, ok := params["congestion_controller"]; ok {
		proxy.CongestionController = cc
	}

	// UDP relay mode
	if urm, ok := params["udp-relay-mode"]; ok {
		proxy.UDPRelayMode = urm
	}
	if urm, ok := params["udp_relay_mode"]; ok {
		proxy.UDPRelayMode = urm
	}

	// reduce-rtt
	if rtt, ok := params["reduce-rtt"]; ok {
		proxy.ReduceRTT = utils.ParseBool(rtt)
	}
	if rtt, ok := params["reduce_rtt"]; ok {
		proxy.ReduceRTT = utils.ParseBool(rtt)
	}

	// skip-cert-verify
	if skip, ok := params["skip-cert-verify"]; ok {
		proxy.SkipCertVerify = utils.ParseBool(skip)
	}
	if skip, ok := params["allow-insecure"]; ok {
		proxy.SkipCertVerify = utils.ParseBool(skip)
	}

	// heartbeat-interval
	if hb, ok := params["heartbeat-interval"]; ok {
		proxy.HeartbeatIntvl = utils.ParseInt(hb, 0)
	}

	return proxy, nil
}

// ParseWireGuard 解析 WireGuard 链接
// 格式: wireguard://privatekey@server:port?params#name
//       wg://privatekey@server:port?params#name
func ParseWireGuard(uri string) (*types.Proxy, error) {
	// 移除协议头
	content := uri
	re := regexp.MustCompile(`^(wireguard|wg)://`)
	content = re.ReplaceAllString(content, "")

	// 正则解析
	re2 := regexp.MustCompile(`^((.*?)@)?(.*?)(:(\d+))?\/?(\?(.*?))?(?:#(.*?))?$`)
	matches := re2.FindStringSubmatch(content)
	if matches == nil {
		return nil, ErrInvalidFormat
	}

	privateKey := utils.URLDecode(matches[2])
	server := matches[3]
	port := utils.ParseInt(matches[5], 51820)
	query := matches[7]
	name := utils.URLDecode(matches[8])

	proxy := &types.Proxy{
		Type:       types.TypeWireGuard,
		Name:       utils.GetIfNotEmpty(name, "WireGuard Node"),
		Server:     server,
		Port:       port,
		PrivateKey: privateKey,
		UDP:        true,
	}

	// 解析参数
	params := utils.ParseQueryString(query)

	// address / ip
	if addr, ok := params["address"]; ok {
		parseWireGuardAddress(proxy, addr)
	}
	if ip, ok := params["ip"]; ok {
		parseWireGuardAddress(proxy, ip)
	}

	// public key
	if pk, ok := params["publickey"]; ok {
		proxy.PublicKey = pk
	}

	// pre-shared-key
	if psk, ok := params["pre-shared-key"]; ok {
		proxy.PreSharedKey = psk
	}

	// allowed-ips
	if ips, ok := params["allowed-ips"]; ok {
		proxy.AllowedIPs = strings.Split(ips, ",")
	}

	// reserved
	if reserved, ok := params["reserved"]; ok {
		parts := strings.Split(reserved, ",")
		var res []int
		for _, p := range parts {
			if v, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
				res = append(res, v)
			}
		}
		if len(res) == 3 {
			proxy.Reserved = res
		}
	}

	// mtu
	if mtu, ok := params["mtu"]; ok {
		proxy.MTU = utils.ParseInt(mtu, 0)
	}

	// dns
	if dns, ok := params["dns"]; ok {
		proxy.DNS = strings.Split(dns, ",")
	}

	// remote-dns-resolve
	if rdr, ok := params["remote-dns-resolve"]; ok {
		proxy.RemoteDNS = utils.ParseBool(rdr)
	}

	return proxy, nil
}

// parseWireGuardAddress 解析 WireGuard 地址
func parseWireGuardAddress(proxy *types.Proxy, addr string) {
	parts := strings.Split(addr, ",")
	for _, p := range parts {
		ip := strings.TrimSpace(p)
		// 移除 CIDR
		ip = strings.Split(ip, "/")[0]
		ip = strings.Trim(ip, "[]")

		if utils.IsIPv4(ip) {
			proxy.IP = ip
		} else if utils.IsIPv6(ip) {
			proxy.IPv6 = ip
		}
	}
}

// ParseHTTP 解析 HTTP 代理链接
// 格式: http://[user:pass@]server:port?params#name
//       https://[user:pass@]server:port?params#name
func ParseHTTP(uri string) (*types.Proxy, error) {
	// 判断是否 HTTPS
	isHTTPS := strings.HasPrefix(uri, "https://")

	// 移除协议头
	content := uri
	re := regexp.MustCompile(`^https?://`)
	content = re.ReplaceAllString(content, "")

	// 正则解析
	re2 := regexp.MustCompile(`^((.*?)@)?(.*?)(:(\d+))?\/?(\?(.*?))?(?:#(.*?))?$`)
	matches := re2.FindStringSubmatch(content)
	if matches == nil {
		return nil, ErrInvalidFormat
	}

	auth := utils.URLDecode(matches[2])
	server := matches[3]
	port := utils.ParseInt(matches[5], 80)
	if isHTTPS && port == 80 {
		port = 443
	}
	query := matches[7]
	name := utils.URLDecode(matches[8])

	proxy := &types.Proxy{
		Type:   types.TypeHTTP,
		Name:   utils.GetIfNotEmpty(name, "HTTP Node"),
		Server: server,
		Port:   port,
		TLS:    isHTTPS,
	}

	// 解析认证信息
	if auth != "" {
		parts := strings.SplitN(auth, ":", 2)
		proxy.Username = parts[0]
		if len(parts) > 1 {
			proxy.Password = parts[1]
		}
	}

	// 解析参数
	params := utils.ParseQueryString(query)

	if tls, ok := params["tls"]; ok {
		proxy.TLS = utils.ParseBool(tls)
	}

	if fp, ok := params["fingerprint"]; ok {
		proxy.Fingerprint = fp
	}

	if skip, ok := params["skip-cert-verify"]; ok {
		proxy.SkipCertVerify = utils.ParseBool(skip)
	}

	return proxy, nil
}

// ParseSOCKS5 解析 SOCKS5 代理链接
// 格式: socks5://[user:pass@]server:port?params#name
func ParseSOCKS5(uri string) (*types.Proxy, error) {
	content := strings.TrimPrefix(uri, "socks5://")

	// 正则解析
	re := regexp.MustCompile(`^((.*?)@)?(.*?)(:(\d+))?\/?(\?(.*?))?(?:#(.*?))?$`)
	matches := re.FindStringSubmatch(content)
	if matches == nil {
		return nil, ErrInvalidFormat
	}

	auth := utils.URLDecode(matches[2])
	server := matches[3]
	port := utils.ParseInt(matches[5], 1080)
	query := matches[7]
	name := utils.URLDecode(matches[8])

	proxy := &types.Proxy{
		Type:   types.TypeSOCKS5,
		Name:   utils.GetIfNotEmpty(name, "SOCKS5 Node"),
		Server: server,
		Port:   port,
	}

	// 解析认证信息
	if auth != "" {
		parts := strings.SplitN(auth, ":", 2)
		proxy.Username = parts[0]
		if len(parts) > 1 {
			proxy.Password = parts[1]
		}
	}

	// 解析参数
	params := utils.ParseQueryString(query)

	if tls, ok := params["tls"]; ok {
		proxy.TLS = utils.ParseBool(tls)
	}

	if fp, ok := params["fingerprint"]; ok {
		proxy.Fingerprint = fp
	}

	if skip, ok := params["skip-cert-verify"]; ok {
		proxy.SkipCertVerify = utils.ParseBool(skip)
	}

	if udp, ok := params["udp"]; ok {
		proxy.UDP = utils.ParseBool(udp)
	}

	return proxy, nil
}
