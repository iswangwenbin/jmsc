package parser

import (
	"encoding/json"
	"regexp"
	"strings"

	"jmsc/pkg/types"
	"jmsc/pkg/utils"
)

// VMess JSON 结构 (V2rayN 格式)
type vmessJSON struct {
	V    string `json:"v"`
	PS   string `json:"ps"`
	Add  string `json:"add"`
	Port any    `json:"port"` // 可能是 string 或 int
	ID   string `json:"id"`
	Aid  any    `json:"aid"` // 可能是 string 或 int
	Scy  string `json:"scy"`
	Net  string `json:"net"`
	Type string `json:"type"`
	Host string `json:"host"`
	Path string `json:"path"`
	TLS  string `json:"tls"`
	SNI  string `json:"sni"`
	ALPN string `json:"alpn"`
	FP   string `json:"fp"`
}

// ParseVMess 解析 VMess 链接
func ParseVMess(uri string) (*types.Proxy, error) {
	content := strings.TrimPrefix(uri, "vmess://")

	// 尝试解码
	decoded := utils.DecodeBase64(content)
	if decoded == "" {
		return nil, ErrInvalidFormat
	}

	// 检查是否是 Quantumult 格式
	if strings.Contains(decoded, "= vmess") {
		return parseQuantumultVMess(decoded)
	}

	// V2rayN JSON 格式
	var vmess vmessJSON

	// 处理可能带有查询参数的情况 (Shadowrocket)
	if !strings.HasPrefix(decoded, "{") {
		// Shadowrocket 格式: method:uuid@server:port?params
		return parseShadowrocketVMess(content)
	}

	if err := json.Unmarshal([]byte(decoded), &vmess); err != nil {
		return nil, ErrInvalidFormat
	}

	proxy := &types.Proxy{
		Type:   types.TypeVMess,
		Name:   utils.TrimString(vmess.PS),
		Server: vmess.Add,
		UUID:   vmess.ID,
		Cipher: utils.GetCipher(utils.GetIfNotEmpty(vmess.Scy, "auto")),
	}

	// 解析端口
	switch p := vmess.Port.(type) {
	case float64:
		proxy.Port = int(p)
	case string:
		proxy.Port = utils.ParseInt(p, 443)
	default:
		proxy.Port = 443
	}

	// 解析 AlterID
	switch a := vmess.Aid.(type) {
	case float64:
		proxy.AlterID = int(a)
	case string:
		proxy.AlterID = utils.ParseInt(a, 0)
	}

	// TLS 设置
	proxy.TLS = vmess.TLS == "tls" || vmess.TLS == "1" || vmess.TLS == "true"
	if proxy.TLS && vmess.SNI != "" {
		proxy.ServerName = vmess.SNI
	}

	// 网络类型
	parseVMessNetwork(proxy, vmess)

	// 设置默认名称
	if proxy.Name == "" {
		proxy.Name = proxy.Server
	}

	return proxy, nil
}

// parseVMessNetwork 解析 VMess 网络配置
func parseVMessNetwork(proxy *types.Proxy, vmess vmessJSON) {
	switch vmess.Net {
	case "ws", "websocket":
		proxy.Network = types.NetworkWS
		proxy.WSOpts = &types.WSOpts{
			Path: utils.GetIfNotEmpty(vmess.Path, "/"),
		}
		if vmess.Host != "" {
			proxy.WSOpts.Headers = map[string]string{"Host": vmess.Host}
		}

	case "h2":
		proxy.Network = types.NetworkH2
		proxy.H2Opts = &types.H2Opts{
			Path: utils.GetIfNotEmpty(vmess.Path, "/"),
		}
		if vmess.Host != "" {
			proxy.H2Opts.Host = []string{vmess.Host}
		}

	case "http":
		proxy.Network = types.NetworkHTTP
		proxy.HTTPOpts = &types.HTTPOpts{
			Path: utils.GetIfNotEmpty(vmess.Path, "/"),
		}
		if vmess.Host != "" {
			proxy.HTTPOpts.Headers = map[string]string{"Host": vmess.Host}
		}

	case "grpc":
		proxy.Network = types.NetworkGRPC
		proxy.GRPCOpts = &types.GRPCOpts{
			GRPCServiceName: vmess.Path,
		}

	case "httpupgrade":
		proxy.Network = types.NetworkWS
		proxy.WSOpts = &types.WSOpts{
			Path:             utils.GetIfNotEmpty(vmess.Path, "/"),
			V2rayHTTPUpgrade: true,
		}
		if vmess.Host != "" {
			proxy.WSOpts.Headers = map[string]string{"Host": vmess.Host}
		}
	}

	// 自动填充 servername
	if proxy.TLS && proxy.ServerName == "" && vmess.Host != "" {
		proxy.ServerName = vmess.Host
	}
}

// parseQuantumultVMess 解析 Quantumult 格式的 VMess
func parseQuantumultVMess(content string) (*types.Proxy, error) {
	parts := strings.Split(content, ",")
	if len(parts) < 5 {
		return nil, ErrInvalidFormat
	}

	proxy := &types.Proxy{
		Type: types.TypeVMess,
	}

	// 解析参数
	params := make(map[string]string)
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "=") {
			kv := strings.SplitN(part, "=", 2)
			params[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}

	// 解析名称
	proxy.Name = strings.TrimSpace(strings.Split(parts[0], "=")[0])

	// 解析服务器和端口
	proxy.Server = strings.TrimSpace(parts[1])
	proxy.Port = utils.ParseInt(parts[2], 443)

	// 解析加密方式
	proxy.Cipher = utils.GetCipher(utils.GetIfNotEmpty(strings.TrimSpace(parts[3]), "auto"))

	// 解析 UUID
	uuidStr := strings.TrimSpace(parts[4])
	uuidStr = strings.Trim(uuidStr, "\"")
	proxy.UUID = uuidStr

	// 处理 obfs
	if obfs, ok := params["obfs"]; ok {
		if obfs == "ws" || obfs == "wss" {
			proxy.Network = types.NetworkWS
			proxy.TLS = obfs == "wss"
			path := "/"
			if p, ok := params["obfs-path"]; ok {
				path = strings.Trim(p, "\"")
			}
			proxy.WSOpts = &types.WSOpts{Path: path}

			if host, ok := params["obfs-header"]; ok {
				re := regexp.MustCompile(`Host:\s*([a-zA-Z0-9\-.]*)`)
				if matches := re.FindStringSubmatch(host); len(matches) > 1 {
					proxy.WSOpts.Headers = map[string]string{"Host": matches[1]}
				}
			}
		}
	}

	return proxy, nil
}

// parseShadowrocketVMess 解析 Shadowrocket 格式的 VMess
func parseShadowrocketVMess(content string) (*types.Proxy, error) {
	// 格式: BASE64(method:uuid@server:port)?params#name
	re := regexp.MustCompile(`^([^?]+?)(\?.*?)?(#.*)?$`)
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

	// 解析 method:uuid@server:port
	re2 := regexp.MustCompile(`^([^:]+?):([^:]+?)@(.*):(\d+)$`)
	matches2 := re2.FindStringSubmatch(decoded)
	if matches2 == nil {
		return nil, ErrInvalidFormat
	}

	proxy := &types.Proxy{
		Type:   types.TypeVMess,
		Cipher: utils.GetCipher(matches2[1]),
		UUID:   matches2[2],
		Server: matches2[3],
		Port:   utils.ParseInt(matches2[4], 443),
	}

	// 解析名称
	if nameHash != "" {
		proxy.Name = utils.URLDecode(strings.TrimPrefix(nameHash, "#"))
	}

	// 解析查询参数
	if query != "" {
		params := utils.ParseQueryString(query)
		if net, ok := params["net"]; ok {
			switch net {
			case "ws":
				proxy.Network = types.NetworkWS
			case "h2":
				proxy.Network = types.NetworkH2
			case "grpc":
				proxy.Network = types.NetworkGRPC
			}
		}
		if host, ok := params["host"]; ok && proxy.Network == types.NetworkWS {
			proxy.WSOpts = &types.WSOpts{
				Headers: map[string]string{"Host": host},
			}
		}
		if path, ok := params["path"]; ok && proxy.WSOpts != nil {
			proxy.WSOpts.Path = path
		}
		if tls, ok := params["tls"]; ok {
			proxy.TLS = utils.ParseBool(tls)
		}
	}

	if proxy.Name == "" {
		proxy.Name = proxy.Server
	}

	return proxy, nil
}
