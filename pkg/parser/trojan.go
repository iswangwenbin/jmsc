package parser

import (
	"regexp"
	"strings"

	"jmsc/pkg/types"
	"jmsc/pkg/utils"
)

// ParseTrojan 解析 Trojan 链接
// 格式: trojan://password@server:port?params#name
func ParseTrojan(uri string) (*types.Proxy, error) {
	content := strings.TrimPrefix(uri, "trojan://")

	// 正则解析
	re := regexp.MustCompile(`^(.*?)@(.*?)(:(\d+))?\/?(\?(.*?))?(?:#(.*?))?$`)
	matches := re.FindStringSubmatch(content)
	if matches == nil {
		return nil, ErrInvalidFormat
	}

	password := utils.URLDecode(matches[1])
	server := matches[2]
	port := utils.ParseInt(matches[4], 443)
	query := matches[6]
	name := utils.URLDecode(matches[7])

	proxy := &types.Proxy{
		Type:     types.TypeTrojan,
		Name:     name,
		Server:   server,
		Port:     port,
		Password: password,
	}

	// 解析参数
	params := utils.ParseQueryString(query)

	// 网络类型
	if netType, ok := params["type"]; ok {
		switch netType {
		case "ws":
			proxy.Network = types.NetworkWS
		case "h2":
			proxy.Network = types.NetworkH2
		case "grpc":
			proxy.Network = types.NetworkGRPC
		default:
			proxy.Network = types.NetworkTCP
		}
	}

	// Host 和 Path
	host := params["host"]
	path := params["path"]

	if proxy.Network == types.NetworkWS {
		proxy.WSOpts = &types.WSOpts{
			Path: path,
		}
		if host != "" {
			proxy.WSOpts.Headers = map[string]string{"Host": host}
		}
	} else if proxy.Network == types.NetworkGRPC {
		proxy.GRPCOpts = &types.GRPCOpts{
			GRPCServiceName: path,
		}
	}

	// ALPN
	if alpn, ok := params["alpn"]; ok && alpn != "" {
		proxy.ALPN = strings.Split(alpn, ",")
	}

	// SNI
	if sni, ok := params["sni"]; ok {
		proxy.SNI = sni
	}

	// Skip cert verify
	if skip, ok := params["skip-cert-verify"]; ok {
		proxy.SkipCertVerify = utils.ParseBool(skip)
	}
	if allow, ok := params["allowinsecure"]; ok {
		proxy.SkipCertVerify = utils.ParseBool(allow)
	}

	// Fingerprint
	if fp, ok := params["fingerprint"]; ok {
		proxy.Fingerprint = fp
	}
	if fp, ok := params["fp"]; ok {
		proxy.Fingerprint = fp
	}

	// Client fingerprint
	if cfp, ok := params["client-fingerprint"]; ok {
		proxy.ClientFP = cfp
	}

	// 设置默认名称
	if proxy.Name == "" {
		proxy.Name = proxy.Server
	}

	return proxy, nil
}
