package parser

import (
	"encoding/base64"
	"errors"
	"strings"

	"jmsc/pkg/types"
)

// ErrUnknownProtocol 未知协议错误
var ErrUnknownProtocol = errors.New("unknown protocol")

// ErrInvalidFormat 格式错误
var ErrInvalidFormat = errors.New("invalid format")

// ParseURI 解析单个代理链接
func ParseURI(uri string) (*types.Proxy, error) {
	uri = strings.TrimSpace(uri)
	if uri == "" {
		return nil, ErrInvalidFormat
	}

	// 获取协议头
	idx := strings.Index(uri, "://")
	if idx == -1 {
		return nil, ErrInvalidFormat
	}
	protocol := strings.ToLower(uri[:idx])

	switch protocol {
	case "ss":
		return ParseSS(uri)
	case "ssr":
		return ParseSSR(uri)
	case "vmess":
		return ParseVMess(uri)
	case "vless":
		return ParseVLESS(uri)
	case "trojan":
		return ParseTrojan(uri)
	case "hysteria2", "hy2":
		return ParseHysteria2(uri)
	case "hysteria", "hy":
		return ParseHysteria(uri)
	case "tuic":
		return ParseTUIC(uri)
	case "wireguard", "wg":
		return ParseWireGuard(uri)
	case "http", "https":
		return ParseHTTP(uri)
	case "socks5":
		return ParseSOCKS5(uri)
	default:
		return nil, ErrUnknownProtocol
	}
}

// ParseMultiple 解析多个代理链接
func ParseMultiple(content string) ([]*types.Proxy, []error) {
	var proxies []*types.Proxy
	var errs []error

	// 尝试 base64 解码整个内容
	decoded := tryDecodeBase64(content)
	if decoded != "" {
		content = decoded
	}

	// 按行分割
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		proxy, err := ParseURI(line)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if proxy != nil {
			proxies = append(proxies, proxy)
		}
	}

	return proxies, errs
}

// tryDecodeBase64 尝试 base64 解码
func tryDecodeBase64(s string) string {
	s = strings.TrimSpace(s)
	// 如果已经包含 :// 则不是 base64
	if strings.Contains(s, "://") {
		return ""
	}
	// 尝试解码
	decoded := decodeBase64Safe(s)
	if decoded != "" && strings.Contains(decoded, "://") {
		return decoded
	}
	return ""
}

func decodeBase64Safe(s string) string {
	// 标准 base64
	if decoded, err := base64.StdEncoding.DecodeString(s); err == nil {
		return string(decoded)
	}
	// URL 安全 base64
	if decoded, err := base64.URLEncoding.DecodeString(s); err == nil {
		return string(decoded)
	}
	// 补充填充后重试
	s = strings.TrimRight(s, "=")
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	if decoded, err := base64.StdEncoding.DecodeString(s); err == nil {
		return string(decoded)
	}
	return ""
}
