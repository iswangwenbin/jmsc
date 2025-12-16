package utils

import (
	"encoding/base64"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

// DecodeBase64 Base64 解码，支持标准和 URL 安全两种格式
func DecodeBase64(s string) string {
	// 先尝试标准 base64
	if decoded, err := base64.StdEncoding.DecodeString(s); err == nil {
		return string(decoded)
	}
	// 尝试 URL 安全 base64
	if decoded, err := base64.URLEncoding.DecodeString(s); err == nil {
		return string(decoded)
	}
	// 尝试无填充的 base64
	s = strings.TrimRight(s, "=")
	// 补充填充
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	if decoded, err := base64.StdEncoding.DecodeString(s); err == nil {
		return string(decoded)
	}
	if decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "=")); err == nil {
		return string(decoded)
	}
	return s
}

// EncodeBase64 Base64 编码
func EncodeBase64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// URLDecode URL 解码
func URLDecode(s string) string {
	decoded, err := url.QueryUnescape(s)
	if err != nil {
		return s
	}
	return decoded
}

// URLEncode URL 编码
func URLEncode(s string) string {
	return url.QueryEscape(s)
}

// ParseQueryString 解析查询字符串
func ParseQueryString(query string) map[string]string {
	result := make(map[string]string)
	if query == "" {
		return result
	}
	// 去掉开头的 ?
	query = strings.TrimPrefix(query, "?")
	pairs := strings.Split(query, "&")
	for _, pair := range pairs {
		if pair == "" {
			continue
		}
		kv := strings.SplitN(pair, "=", 2)
		key := kv[0]
		value := ""
		if len(kv) > 1 {
			value = URLDecode(kv[1])
		}
		result[strings.ToLower(key)] = value
	}
	return result
}

// GetIfNotEmpty 如果字符串非空则返回，否则返回默认值
func GetIfNotEmpty(value, defaultVal string) string {
	if strings.TrimSpace(value) != "" {
		return value
	}
	return defaultVal
}

// ParseInt 解析整数，失败返回默认值
func ParseInt(s string, defaultVal int) int {
	if s == "" {
		return defaultVal
	}
	// 提取数字部分
	re := regexp.MustCompile(`\d+`)
	match := re.FindString(s)
	if match == "" {
		return defaultVal
	}
	val, err := strconv.Atoi(match)
	if err != nil {
		return defaultVal
	}
	return val
}

// ParseBool 解析布尔值
func ParseBool(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "true" || s == "1" || s == "yes"
}

// IsIPv4 判断是否为 IPv4 地址
func IsIPv4(address string) bool {
	re := regexp.MustCompile(`^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$`)
	return re.MatchString(address)
}

// IsIPv6 判断是否为 IPv6 地址
func IsIPv6(address string) bool {
	re := regexp.MustCompile(`^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::$|^::1$|^([0-9a-fA-F]{1,4}:)*::([0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}$`)
	return re.MatchString(address)
}

// PunycodeDomain 将国际化域名转换为 Punycode
func PunycodeDomain(domain string) string {
	// 如果是 IP 地址，直接返回
	if IsIPv4(domain) || IsIPv6(domain) {
		return domain
	}
	// 尝试转换
	ascii, err := idna.ToASCII(domain)
	if err != nil {
		return domain
	}
	return ascii
}

// SplitHostPort 分离 host 和 port，支持 IPv6
func SplitHostPort(hostPort string) (host string, port int) {
	// 处理 IPv6 格式 [::1]:port
	if strings.HasPrefix(hostPort, "[") {
		idx := strings.LastIndex(hostPort, "]:")
		if idx != -1 {
			host = hostPort[1:idx]
			port = ParseInt(hostPort[idx+2:], 0)
			return
		}
		// 没有端口
		host = strings.Trim(hostPort, "[]")
		return
	}
	// 普通格式
	idx := strings.LastIndex(hostPort, ":")
	if idx != -1 {
		host = hostPort[:idx]
		port = ParseInt(hostPort[idx+1:], 0)
		return
	}
	host = hostPort
	return
}

// GetCipher 标准化加密方式
func GetCipher(cipher string) string {
	cipherMap := map[string]string{
		"none":                     "none",
		"auto":                     "auto",
		"dummy":                    "dummy",
		"aes-128-gcm":              "aes-128-gcm",
		"aes-192-gcm":              "aes-192-gcm",
		"aes-256-gcm":              "aes-256-gcm",
		"chacha20-ietf-poly1305":   "chacha20-ietf-poly1305",
		"xchacha20-ietf-poly1305":  "xchacha20-ietf-poly1305",
		"2022-blake3-aes-128-gcm":  "2022-blake3-aes-128-gcm",
		"2022-blake3-aes-256-gcm":  "2022-blake3-aes-256-gcm",
		"2022-blake3-chacha20-poly1305": "2022-blake3-chacha20-poly1305",
	}
	if mapped, ok := cipherMap[strings.ToLower(cipher)]; ok {
		return mapped
	}
	return "auto"
}

// TrimString 去除字符串首尾空白
func TrimString(s string) string {
	return strings.TrimSpace(s)
}

// SplitLines 按行分割字符串
func SplitLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	lines := strings.Split(s, "\n")
	var result []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}
