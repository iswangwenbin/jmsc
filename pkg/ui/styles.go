package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// 颜色定义
var (
	primaryColor   = lipgloss.Color("#7C3AED") // 紫色
	successColor   = lipgloss.Color("#10B981") // 绿色
	warningColor   = lipgloss.Color("#F59E0B") // 黄色
	errorColor     = lipgloss.Color("#EF4444") // 红色
	mutedColor     = lipgloss.Color("#6B7280") // 灰色
	highlightColor = lipgloss.Color("#3B82F6") // 蓝色
)

// 样式定义
var (
	// Logo 样式
	LogoStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(primaryColor)

	// 标题样式
	TitleStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#FFFFFF")).
		Background(primaryColor).
		Padding(0, 1)

	// 成功样式
	SuccessStyle = lipgloss.NewStyle().
		Foreground(successColor).
		Bold(true)

	// 警告样式
	WarningStyle = lipgloss.NewStyle().
		Foreground(warningColor)

	// 错误样式
	ErrorStyle = lipgloss.NewStyle().
		Foreground(errorColor).
		Bold(true)

	// 信息样式
	InfoStyle = lipgloss.NewStyle().
		Foreground(highlightColor)

	// 暗淡样式
	MutedStyle = lipgloss.NewStyle().
		Foreground(mutedColor)

	// 代码样式
	CodeStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#E879F9")).
		Background(lipgloss.Color("#1F2937")).
		Padding(0, 1)

	// 边框样式
	BoxStyle = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(primaryColor).
		Padding(0, 1)

	// 协议标签样式
	ProtocolStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#FFFFFF")).
		Background(highlightColor).
		Padding(0, 1).
		Bold(true)

	// 数字高亮
	NumberStyle = lipgloss.NewStyle().
		Foreground(successColor).
		Bold(true)
)

// Logo ASCII 艺术
const logoASCII = `
     ██╗███╗   ███╗███████╗ ██████╗
     ██║████╗ ████║██╔════╝██╔════╝
     ██║██╔████╔██║███████╗██║
██   ██║██║╚██╔╝██║╚════██║██║
╚█████╔╝██║ ╚═╝ ██║███████║╚██████╗
 ╚════╝ ╚═╝     ╚═╝╚══════╝ ╚═════╝`

// Version 版本号，由 main 包设置
var Version = "dev"

// PrintLogo 打印 Logo
func PrintLogo() {
	fmt.Println(LogoStyle.Render(logoASCII))
	fmt.Println(MutedStyle.Render("JustMySocks to Clash " + Version))
	fmt.Println()
}

// PrintHelp 打印美化的帮助信息
func PrintHelp() {
	PrintLogo()

	// 用法
	fmt.Println(TitleStyle.Render(" 用法 Usage "))
	fmt.Println()
	examples := []string{
		"jmsc [选项] [链接...]",
		"jmsc -i input.txt -o output.yaml",
		"jmsc -u https://example.com/sub",
		"echo \"ss://...\" | jmsc",
	}
	for _, ex := range examples {
		fmt.Printf("  %s\n", CodeStyle.Render(ex))
	}
	fmt.Println()

	// 选项
	fmt.Println(TitleStyle.Render(" 选项 Options "))
	fmt.Println()
	options := [][]string{
		{"-i, --input", "输入文件路径"},
		{"-o, --output", "输出文件路径"},
		{"-u, --url", "订阅 URL"},
		{"-m, --mode", "输出模式: proxies (默认), payload, none"},
		{"-r, --reverse", "反向转换: Clash YAML -> 分享链接"},
		{"-v, --version", "显示版本"},
		{"-h, --help", "显示帮助"},
	}
	for _, opt := range options {
		fmt.Printf("  %s  %s\n",
			InfoStyle.Render(fmt.Sprintf("%-14s", opt[0])),
			MutedStyle.Render(opt[1]))
	}
	fmt.Println()

	// 支持的协议
	fmt.Println(TitleStyle.Render(" 支持的协议 Protocols "))
	fmt.Println()
	protocols := [][]string{
		{"SS", "ss://"},
		{"SSR", "ssr://"},
		{"VMess", "vmess://"},
		{"VLESS", "vless://"},
		{"Trojan", "trojan://"},
		{"Hysteria", "hy://"},
		{"Hysteria2", "hy2://"},
		{"TUIC", "tuic://"},
		{"WireGuard", "wg://"},
		{"HTTP", "http://"},
		{"SOCKS5", "socks5://"},
	}

	var protocolTags []string
	for _, p := range protocols {
		tag := lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(getProtocolColor(p[0])).
			Padding(0, 1).
			Render(p[0])
		protocolTags = append(protocolTags, tag)
	}
	fmt.Println("  " + strings.Join(protocolTags, " "))
	fmt.Println()

	// 示例
	fmt.Println(TitleStyle.Render(" 示例 Examples "))
	fmt.Println()
	exampleCmds := [][]string{
		{"# 转换单个链接", "jmsc \"ss://...\""},
		{"# 从文件转换", "jmsc -i links.txt -o clash.yaml"},
		{"# 从订阅 URL 转换", "jmsc -u https://example.com/sub -o clash.yaml"},
		{"# 反向转换", "jmsc -r -i clash.yaml"},
		{"# 管道输入", "cat links.txt | jmsc > clash.yaml"},
	}
	for _, cmd := range exampleCmds {
		fmt.Printf("  %s\n", MutedStyle.Render(cmd[0]))
		fmt.Printf("  %s\n\n", CodeStyle.Render(cmd[1]))
	}
}

// PrintSuccess 打印成功信息
func PrintSuccess(msg string) {
	icon := SuccessStyle.Render("✓")
	fmt.Printf("%s %s\n", icon, msg)
}

// PrintError 打印错误信息
func PrintError(msg string) {
	icon := ErrorStyle.Render("✗")
	fmt.Printf("%s %s\n", icon, ErrorStyle.Render(msg))
}

// PrintWarning 打印警告信息
func PrintWarning(msg string) {
	icon := WarningStyle.Render("!")
	fmt.Printf("%s %s\n", icon, WarningStyle.Render(msg))
}

// PrintInfo 打印信息
func PrintInfo(msg string) {
	icon := InfoStyle.Render("→")
	fmt.Printf("%s %s\n", icon, msg)
}

// PrintStats 打印统计信息
func PrintStats(total, success, failed int) {
	fmt.Println()
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(primaryColor).
		Padding(0, 2).
		Render(fmt.Sprintf(
			"%s %s  %s %s  %s %s",
			MutedStyle.Render("总计:"),
			NumberStyle.Render(fmt.Sprintf("%d", total)),
			MutedStyle.Render("成功:"),
			SuccessStyle.Render(fmt.Sprintf("%d", success)),
			MutedStyle.Render("失败:"),
			ErrorStyle.Render(fmt.Sprintf("%d", failed)),
		))
	fmt.Println(box)
}

// PrintVersion 打印版本信息
func PrintVersion() {
	fmt.Printf("%s %s\n",
		LogoStyle.Render("jmsc"),
		MutedStyle.Render("version "+Version))
}

// PrintSaved 打印保存成功信息
func PrintSaved(path string) {
	PrintSuccess(fmt.Sprintf("已保存到: %s", InfoStyle.Render(path)))
}

// getProtocolColor 根据协议返回颜色
func getProtocolColor(protocol string) lipgloss.Color {
	colors := map[string]lipgloss.Color{
		"SS":        lipgloss.Color("#6366F1"), // Indigo
		"SSR":       lipgloss.Color("#8B5CF6"), // Violet
		"VMess":     lipgloss.Color("#EC4899"), // Pink
		"VLESS":     lipgloss.Color("#F43F5E"), // Rose
		"Trojan":    lipgloss.Color("#F59E0B"), // Amber
		"Hysteria":  lipgloss.Color("#10B981"), // Emerald
		"Hysteria2": lipgloss.Color("#14B8A6"), // Teal
		"TUIC":      lipgloss.Color("#06B6D4"), // Cyan
		"WireGuard": lipgloss.Color("#3B82F6"), // Blue
		"HTTP":      lipgloss.Color("#6B7280"), // Gray
		"SOCKS5":    lipgloss.Color("#78716C"), // Stone
	}
	if c, ok := colors[protocol]; ok {
		return c
	}
	return lipgloss.Color("#6B7280")
}
