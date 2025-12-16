package parser

import (
	"strings"

	"jmsc/pkg/types"
	"jmsc/pkg/utils"
)

// ParseSS 解析 Shadowsocks 链接
// 格式: ss://BASE64(method:password)@server:port#name
// 或:   ss://BASE64(method:password@server:port)#name
func ParseSS(uri string) (*types.Proxy, error) {
	// 移除协议头
	content := strings.TrimPrefix(uri, "ss://")

	proxy := &types.Proxy{
		Type: types.TypeSS,
	}

	// 提取节点名称 (# 后面的部分)
	if idx := strings.LastIndex(uri, "#"); idx != -1 {
		proxy.Name = utils.TrimString(utils.URLDecode(uri[idx+1:]))
		content = content[:strings.LastIndex(content, "#")]
	}

	var userInfo, serverPart, query string

	// 检查是否有 @ 符号（SIP002 格式）
	if strings.Contains(content, "@") {
		// 处理查询参数
		if qIdx := strings.Index(content, "?"); qIdx != -1 {
			query = content[qIdx+1:]
			content = content[:qIdx]
		}

		// 分离用户信息和服务器信息
		atIdx := strings.LastIndex(content, "@")
		userInfoPart := content[:atIdx]
		serverPart = content[atIdx+1:]

		// 用户信息可能是 base64 编码的
		userInfo = utils.DecodeBase64(userInfoPart)
		if !strings.Contains(userInfo, ":") {
			userInfo = userInfoPart
		}
	} else {
		// 旧格式：整个内容都是 base64 编码的
		if qIdx := strings.Index(content, "?"); qIdx != -1 {
			query = content[qIdx+1:]
			content = content[:qIdx]
		}
		decoded := utils.DecodeBase64(content)
		if decoded == "" {
			return nil, ErrInvalidFormat
		}
		// 格式: method:password@server:port
		atIdx := strings.LastIndex(decoded, "@")
		if atIdx == -1 {
			return nil, ErrInvalidFormat
		}
		userInfo = decoded[:atIdx]
		serverPart = decoded[atIdx+1:]
	}

	// 解析服务器地址和端口
	host, port := utils.SplitHostPort(serverPart)
	proxy.Server = host
	proxy.Port = port
	if proxy.Port == 0 {
		proxy.Port = 443
	}

	// 解析加密方式和密码
	colonIdx := strings.Index(userInfo, ":")
	if colonIdx != -1 {
		proxy.Cipher = utils.GetCipher(userInfo[:colonIdx])
		proxy.Password = userInfo[colonIdx+1:]
	}

	// 设置默认名称
	if proxy.Name == "" {
		proxy.Name = proxy.Server
	}

	// 解析插件参数
	if query != "" {
		parseSSPlugin(proxy, query)
	}

	return proxy, nil
}

// parseSSPlugin 解析 SS 插件参数
func parseSSPlugin(proxy *types.Proxy, query string) {
	params := utils.ParseQueryString(query)

	// 处理 plugin 参数
	if plugin, ok := params["plugin"]; ok {
		pluginParts := strings.Split(plugin, ";")
		pluginName := pluginParts[0]

		pluginOpts := make(map[string]any)
		for i := 1; i < len(pluginParts); i++ {
			kv := strings.SplitN(pluginParts[i], "=", 2)
			if len(kv) == 2 {
				pluginOpts[kv[0]] = kv[1]
			} else if len(kv) == 1 && kv[0] != "" {
				pluginOpts[kv[0]] = true
			}
		}

		switch pluginName {
		case "obfs-local", "simple-obfs":
			proxy.Plugin = "obfs"
			proxy.PluginOpts = map[string]any{
				"mode": pluginOpts["obfs"],
				"host": pluginOpts["obfs-host"],
			}
		case "v2ray-plugin":
			proxy.Plugin = "v2ray-plugin"
			proxy.PluginOpts = map[string]any{
				"mode": "websocket",
				"host": pluginOpts["obfs-host"],
				"path": pluginOpts["path"],
				"tls":  pluginOpts["tls"],
			}
		}
	}

	// 处理 uot 参数
	if uot, ok := params["uot"]; ok && utils.ParseBool(uot) {
		proxy.UDPOverTCP = true
	}

	// 处理 tfo 参数
	if tfo, ok := params["tfo"]; ok && utils.ParseBool(tfo) {
		proxy.TFO = true
	}
}

// ParseSSR 解析 ShadowsocksR 链接
// 格式: ssr://BASE64(server:port:protocol:method:obfs:base64(password)/?params)
func ParseSSR(uri string) (*types.Proxy, error) {
	content := strings.TrimPrefix(uri, "ssr://")
	decoded := utils.DecodeBase64(content)
	if decoded == "" {
		return nil, ErrInvalidFormat
	}

	proxy := &types.Proxy{
		Type: types.TypeSSR,
		Name: "SSR",
	}

	// 分离主体和参数
	mainPart := decoded
	paramPart := ""
	if idx := strings.Index(decoded, "/?"); idx != -1 {
		mainPart = decoded[:idx]
		paramPart = decoded[idx+2:]
	}

	// 查找协议分隔符
	var splitIdx int
	if idx := strings.Index(mainPart, ":origin"); idx != -1 {
		splitIdx = idx
	} else if idx := strings.Index(mainPart, ":auth_"); idx != -1 {
		splitIdx = idx
	} else {
		// 尝试按 : 分割
		parts := strings.Split(mainPart, ":")
		if len(parts) < 6 {
			return nil, ErrInvalidFormat
		}
		// 处理 IPv6
		if len(parts) > 6 {
			// 可能是 IPv6 地址
			lastColonIdx := strings.LastIndex(mainPart, ":")
			for i := 0; i < 5; i++ {
				lastColonIdx = strings.LastIndex(mainPart[:lastColonIdx], ":")
			}
			splitIdx = lastColonIdx
		} else {
			splitIdx = strings.LastIndex(mainPart[:strings.LastIndex(mainPart, ":")], ":")
		}
	}

	// 解析服务器和端口
	serverAndPort := mainPart[:splitIdx]
	lastColonIdx := strings.LastIndex(serverAndPort, ":")
	proxy.Server = serverAndPort[:lastColonIdx]
	proxy.Port = utils.ParseInt(serverAndPort[lastColonIdx+1:], 443)

	// 解析协议参数
	rest := mainPart[splitIdx+1:]
	parts := strings.Split(rest, ":")
	if len(parts) >= 4 {
		proxy.Protocol = parts[0]
		proxy.Cipher = utils.GetCipher(parts[1])
		proxy.Obfs = parts[2]
		proxy.Password = utils.DecodeBase64(parts[3])
	}

	// 解析额外参数
	if paramPart != "" {
		params := utils.ParseQueryString(paramPart)
		if remarks, ok := params["remarks"]; ok {
			proxy.Name = utils.TrimString(utils.DecodeBase64(remarks))
		}
		if protoParam, ok := params["protoparam"]; ok {
			proxy.ProtocolParam = strings.ReplaceAll(utils.DecodeBase64(protoParam), " ", "")
		}
		if obfsParam, ok := params["obfsparam"]; ok {
			proxy.ObfsParam = strings.ReplaceAll(utils.DecodeBase64(obfsParam), " ", "")
		}
	}

	if proxy.Name == "" {
		proxy.Name = proxy.Server
	}

	return proxy, nil
}
