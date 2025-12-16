package parser

import (
	"regexp"
	"strings"

	"jmsc/pkg/types"
	"jmsc/pkg/utils"
)

// ParseHysteria2 解析 Hysteria2 链接
// 格式: hysteria2://password@server:port?params#name
//       hy2://password@server:port?params#name
func ParseHysteria2(uri string) (*types.Proxy, error) {
	// 移除协议头
	content := uri
	content = strings.TrimPrefix(content, "hysteria2://")
	content = strings.TrimPrefix(content, "hy2://")

	// 分离 # 前后
	hashIdx := strings.LastIndex(content, "#")
	var name string
	if hashIdx != -1 {
		name = utils.URLDecode(content[hashIdx+1:])
		content = content[:hashIdx]
	}

	// 找到 @ 分离密码和地址
	atIdx := strings.LastIndex(content, "@")
	if atIdx == -1 {
		return nil, ErrInvalidFormat
	}

	password := utils.URLDecode(content[:atIdx])
	addrAndQuery := content[atIdx+1:]

	// 分离地址和查询参数
	queryIdx := strings.Index(addrAndQuery, "?")
	var addr, query string
	if queryIdx != -1 {
		addr = addrAndQuery[:queryIdx]
		query = addrAndQuery[queryIdx+1:]
	} else {
		addr = addrAndQuery
	}

	// 解析 server:port
	host, port := utils.SplitHostPort(addr)
	if port == 0 {
		port = 443
	}

	proxy := &types.Proxy{
		Type:     types.TypeHysteria2,
		Name:     utils.GetIfNotEmpty(name, "Hysteria2 Node"),
		Server:   host,
		Port:     port,
		Password: password,
	}

	// 解析参数
	params := utils.ParseQueryString(query)

	// insecure
	if insecure, ok := params["insecure"]; ok && insecure == "1" {
		proxy.SkipCertVerify = true
	}

	// SNI
	if sni, ok := params["sni"]; ok {
		proxy.SNI = sni
	}

	// obfs
	if obfs, ok := params["obfs"]; ok {
		proxy.Obfs = obfs
	}

	// obfs-password
	if obfsPwd, ok := params["obfs-password"]; ok {
		proxy.ObfsPassword = obfsPwd
	}

	// ALPN
	if alpn, ok := params["alpn"]; ok && alpn != "" {
		proxy.ALPN = strings.Split(alpn, ",")
	}

	// Fingerprint
	if fp, ok := params["fp"]; ok {
		proxy.Fingerprint = fp
	}
	if fp, ok := params["fingerprint"]; ok {
		proxy.Fingerprint = fp
	}

	return proxy, nil
}

// ParseHysteria 解析 Hysteria (v1) 链接
// 格式: hysteria://server:port?params#name
//       hy://server:port?params#name
func ParseHysteria(uri string) (*types.Proxy, error) {
	// 移除协议头
	content := uri
	re := regexp.MustCompile(`^(hysteria|hy)://`)
	content = re.ReplaceAllString(content, "")

	// 正则解析
	re2 := regexp.MustCompile(`^(.*?)(:(\d+))?\/?(\?(.*?))?(?:#(.*?))?$`)
	matches := re2.FindStringSubmatch(content)
	if matches == nil {
		return nil, ErrInvalidFormat
	}

	server := matches[1]
	port := utils.ParseInt(matches[3], 443)
	query := matches[5]
	name := utils.URLDecode(matches[6])

	proxy := &types.Proxy{
		Type:     types.TypeHysteria,
		Name:     utils.GetIfNotEmpty(name, "Hysteria Node"),
		Server:   server,
		Port:     port,
		Protocol: "udp",
	}

	// 解析参数
	params := utils.ParseQueryString(query)

	// auth
	if auth, ok := params["auth"]; ok {
		proxy.AuthStr = auth
	}

	// ALPN
	if alpn, ok := params["alpn"]; ok && alpn != "" {
		proxy.ALPN = strings.Split(alpn, ",")
	}

	// insecure
	if insecure, ok := params["insecure"]; ok {
		proxy.SkipCertVerify = utils.ParseBool(insecure)
	}

	// mport (端口跳跃)
	if mport, ok := params["mport"]; ok {
		proxy.Ports = mport
	}

	// obfs / obfsParam
	if obfs, ok := params["obfs"]; ok {
		proxy.Obfs = obfs
	}
	if obfsParam, ok := params["obfsparam"]; ok {
		proxy.Obfs = obfsParam
	}

	// up/down
	if up, ok := params["upmbps"]; ok {
		proxy.Up = up
	}
	if down, ok := params["downmbps"]; ok {
		proxy.Down = down
	}

	// SNI
	if sni, ok := params["sni"]; ok {
		proxy.SNI = sni
	}
	if peer, ok := params["peer"]; ok && proxy.SNI == "" {
		proxy.SNI = peer
	}

	// fast-open
	if fo, ok := params["fast-open"]; ok {
		proxy.FastOpen = utils.ParseBool(fo)
	}

	// fingerprint
	if fp, ok := params["fingerprint"]; ok {
		proxy.Fingerprint = fp
	}

	return proxy, nil
}
