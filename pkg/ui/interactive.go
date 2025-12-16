package ui

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/huh/spinner"
	"github.com/charmbracelet/lipgloss"
)

// InteractiveConfig 交互式配置结果
type InteractiveConfig struct {
	InputSource string // "url", "file", "paste"
	InputURL    string
	InputFile   string
	InputText   string
	OutputFile  string
	SaveToFile  bool
}

// RunInteractive 运行交互式模式
func RunInteractive() (*InteractiveConfig, error) {
	PrintLogo()

	config := &InteractiveConfig{
		SaveToFile: true, // 默认保存到文件
	}

	// 第一步：选择输入来源
	inputSourceForm := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("选择输入来源").
				Description("从哪里获取订阅数据？").
				Options(
					huh.NewOption("🌐 订阅 URL", "url"),
					huh.NewOption("📄 本地文件", "file"),
					huh.NewOption("📋 直接粘贴", "paste"),
				).
				Value(&config.InputSource),
		),
	).WithTheme(getHuhTheme())

	err := inputSourceForm.Run()
	if err != nil {
		return nil, err
	}

	// 第二步：根据输入来源获取输入
	switch config.InputSource {
	case "url":
		urlForm := huh.NewForm(
			huh.NewGroup(
				huh.NewInput().
					Title("输入订阅 URL").
					Description("请输入完整的订阅地址").
					Placeholder("https://example.com/subscribe").
					Value(&config.InputURL).
					Validate(func(s string) error {
						if s == "" {
							return fmt.Errorf("URL 不能为空")
						}
						if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
							return fmt.Errorf("请输入有效的 URL")
						}
						return nil
					}),
			),
		).WithTheme(getHuhTheme())

		err = urlForm.Run()
		if err != nil {
			return nil, err
		}

	case "file":
		fileForm := huh.NewForm(
			huh.NewGroup(
				huh.NewInput().
					Title("输入文件路径").
					Description("请输入文件的完整路径").
					Placeholder("/path/to/links.txt").
					Value(&config.InputFile).
					Validate(func(s string) error {
						if s == "" {
							return fmt.Errorf("文件路径不能为空")
						}
						if _, err := os.Stat(s); os.IsNotExist(err) {
							return fmt.Errorf("文件不存在")
						}
						return nil
					}),
			),
		).WithTheme(getHuhTheme())

		err = fileForm.Run()
		if err != nil {
			return nil, err
		}

	case "paste":
		pasteForm := huh.NewForm(
			huh.NewGroup(
				huh.NewText().
					Title("粘贴链接").
					Description("粘贴代理链接（每行一个，支持 ss/vmess/vless/trojan 等）").
					Placeholder("ss://...\nvmess://...\nvless://...").
					Value(&config.InputText).
					CharLimit(50000).
					Validate(func(s string) error {
						if strings.TrimSpace(s) == "" {
							return fmt.Errorf("内容不能为空")
						}
						return nil
					}),
			),
		).WithTheme(getHuhTheme())

		err = pasteForm.Run()
		if err != nil {
			return nil, err
		}
	}

	// 第三步：选择输出方式，默认文件名带时间戳
	defaultFileName := fmt.Sprintf("clash_%s.yaml", time.Now().Format("20060102_150405"))
	config.OutputFile = defaultFileName

	outputForm := huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title("保存到文件?").
				Description("是否将结果保存到文件？").
				Affirmative("是，保存到文件").
				Negative("否，输出到终端").
				Value(&config.SaveToFile),
		),
	).WithTheme(getHuhTheme())

	err = outputForm.Run()
	if err != nil {
		return nil, err
	}

	if config.SaveToFile {
		fileForm := huh.NewForm(
			huh.NewGroup(
				huh.NewInput().
					Title("输出文件路径").
					Description("保存结果的文件路径").
					Value(&config.OutputFile).
					Validate(func(s string) error {
						if s == "" {
							return fmt.Errorf("文件路径不能为空")
						}
						return nil
					}),
			),
		).WithTheme(getHuhTheme())

		err = fileForm.Run()
		if err != nil {
			return nil, err
		}
	}

	return config, nil
}

// RunSpinner 显示加载动画
func RunSpinner(title string, action func()) error {
	return spinner.New().
		Title(title).
		Style(lipgloss.NewStyle().Foreground(primaryColor)).
		Action(action).
		Run()
}

// getHuhTheme 获取 huh 表单主题
func getHuhTheme() *huh.Theme {
	t := huh.ThemeCharm()

	// 自定义颜色
	t.Focused.Title = t.Focused.Title.Foreground(primaryColor).Bold(true)
	t.Focused.Description = t.Focused.Description.Foreground(mutedColor)
	t.Focused.SelectedOption = t.Focused.SelectedOption.Foreground(successColor)
	t.Focused.SelectSelector = t.Focused.SelectSelector.Foreground(primaryColor)

	return t
}

// PrintInteractiveResult 打印交互式结果
func PrintInteractiveResult(total, success, failed int, outputFile string) {
	fmt.Println()
	if outputFile != "" {
		PrintSaved(outputFile)
	}
	PrintStats(total, success, failed)
}
