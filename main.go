package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"jmsc/pkg/generator"
	"jmsc/pkg/parser"
	"jmsc/pkg/ui"
)

// 版本信息，由构建时注入
var (
	version   = "dev"
	buildTime = ""
)

func main() {
	// 设置版本号
	ui.Version = version

	// 定义命令行参数
	var (
		inputFile   string
		outputFile  string
		inputURL    string
		mode        string
		reverse     bool
		showVersion bool
		showHelp    bool
		quiet       bool
		interactive bool
	)

	flag.StringVar(&inputFile, "i", "", "输入文件路径")
	flag.StringVar(&inputFile, "input", "", "输入文件路径")
	flag.StringVar(&outputFile, "o", "", "输出文件路径")
	flag.StringVar(&outputFile, "output", "", "输出文件路径")
	flag.StringVar(&inputURL, "u", "", "订阅 URL")
	flag.StringVar(&inputURL, "url", "", "订阅 URL")
	flag.StringVar(&mode, "m", "proxies", "输出模式: proxies, payload, none")
	flag.StringVar(&mode, "mode", "proxies", "输出模式: proxies, payload, none")
	flag.BoolVar(&reverse, "r", false, "反向转换: Clash -> 链接")
	flag.BoolVar(&reverse, "reverse", false, "反向转换: Clash -> 链接")
	flag.BoolVar(&showVersion, "v", false, "显示版本")
	flag.BoolVar(&showVersion, "version", false, "显示版本")
	flag.BoolVar(&showHelp, "h", false, "显示帮助")
	flag.BoolVar(&showHelp, "help", false, "显示帮助")
	flag.BoolVar(&quiet, "q", false, "安静模式，只输出结果")
	flag.BoolVar(&quiet, "quiet", false, "安静模式，只输出结果")
	flag.BoolVar(&interactive, "I", false, "交互式模式")
	flag.BoolVar(&interactive, "interactive", false, "交互式模式")

	flag.Parse()

	if showVersion {
		ui.PrintVersion()
		return
	}

	if showHelp {
		ui.PrintHelp()
		return
	}

	// 检查是否有管道输入
	stat, _ := os.Stdin.Stat()
	hasPipeInput := (stat.Mode() & os.ModeCharDevice) == 0

	// 如果没有任何参数且没有管道输入，启动交互式模式
	if !interactive && !hasPipeInput && inputFile == "" && inputURL == "" && flag.NArg() == 0 {
		interactive = true
	}

	// 交互式模式
	if interactive {
		runInteractiveMode()
		return
	}

	// 命令行模式
	runCommandLineMode(inputFile, outputFile, inputURL, mode, reverse, quiet)
}

// runInteractiveMode 运行交互式模式
func runInteractiveMode() {
	config, err := ui.RunInteractive()
	if err != nil {
		if err.Error() == "user aborted" {
			fmt.Println()
			ui.PrintInfo("已取消操作")
			return
		}
		ui.PrintError(fmt.Sprintf("交互式模式错误: %v", err))
		os.Exit(1)
	}

	// 获取输入内容
	var content string

	switch config.InputSource {
	case "url":
		var fetchErr error
		ui.RunSpinner("正在获取订阅...", func() {
			content, fetchErr = fetchURL(config.InputURL)
		})
		if fetchErr != nil {
			ui.PrintError(fmt.Sprintf("获取订阅失败: %v", fetchErr))
			os.Exit(1)
		}
		ui.PrintSuccess("订阅获取成功")

	case "file":
		data, err := os.ReadFile(config.InputFile)
		if err != nil {
			ui.PrintError(fmt.Sprintf("读取文件失败: %v", err))
			os.Exit(1)
		}
		content = string(data)

	case "paste":
		content = config.InputText
	}

	// 执行转换
	var result string
	var total, success, failed int
	var convertErr error

	ui.RunSpinner("正在转换...", func() {
		result, total, success, failed, convertErr = linksToClash(content, "proxies", true)
	})

	if convertErr != nil {
		ui.PrintError(fmt.Sprintf("转换失败: %v", convertErr))
		os.Exit(1)
	}

	ui.PrintSuccess("转换完成")

	// 输出结果
	if config.SaveToFile && config.OutputFile != "" {
		err := os.WriteFile(config.OutputFile, []byte(result), 0644)
		if err != nil {
			ui.PrintError(fmt.Sprintf("写入文件失败: %v", err))
			os.Exit(1)
		}
		ui.PrintInteractiveResult(total, success, failed, config.OutputFile)
	} else {
		ui.PrintStats(total, success, failed)
		fmt.Println()
		fmt.Println(ui.MutedStyle.Render("─────────────────────────────────────"))
		fmt.Println()
		fmt.Print(result)
	}
}

// runCommandLineMode 运行命令行模式
func runCommandLineMode(inputFile, outputFile, inputURL, mode string, reverse, quiet bool) {
	// 获取输入内容
	var content string
	var err error
	var inputSource string

	if inputURL != "" {
		inputSource = "url"
		if !quiet {
			ui.PrintInfo(fmt.Sprintf("正在获取订阅: %s", ui.InfoStyle.Render(inputURL)))
		}
		content, err = fetchURL(inputURL)
		if err != nil {
			ui.PrintError(fmt.Sprintf("获取订阅失败: %v", err))
			os.Exit(1)
		}
		if !quiet {
			ui.PrintSuccess("订阅获取成功")
		}
	} else if inputFile != "" {
		inputSource = "file"
		if !quiet {
			ui.PrintInfo(fmt.Sprintf("正在读取文件: %s", ui.InfoStyle.Render(inputFile)))
		}
		data, err := os.ReadFile(inputFile)
		if err != nil {
			ui.PrintError(fmt.Sprintf("读取文件失败: %v", err))
			os.Exit(1)
		}
		content = string(data)
	} else if flag.NArg() > 0 {
		inputSource = "args"
		content = strings.Join(flag.Args(), "\n")
	} else {
		inputSource = "stdin"
		content, err = readStdin()
		if err != nil {
			ui.PrintError(fmt.Sprintf("读取输入失败: %v", err))
			os.Exit(1)
		}
	}

	if strings.TrimSpace(content) == "" {
		if inputSource == "stdin" {
			ui.PrintHelp()
		} else {
			ui.PrintError("输入内容为空")
		}
		os.Exit(1)
	}

	// 执行转换
	var result string
	var total, success, failed int

	if reverse {
		if !quiet {
			ui.PrintInfo("执行反向转换: Clash → 链接")
		}
		result, total, success, failed, err = clashToLinks(content)
	} else {
		if !quiet {
			ui.PrintInfo(fmt.Sprintf("执行转换: 链接 → Clash (%s 模式)", ui.CodeStyle.Render(mode)))
		}
		result, total, success, failed, err = linksToClash(content, mode, quiet)
	}

	if err != nil {
		ui.PrintError(fmt.Sprintf("转换失败: %v", err))
		os.Exit(1)
	}

	// 输出结果
	if outputFile != "" {
		err = os.WriteFile(outputFile, []byte(result), 0644)
		if err != nil {
			ui.PrintError(fmt.Sprintf("写入文件失败: %v", err))
			os.Exit(1)
		}
		ui.PrintSaved(outputFile)
		if !quiet {
			ui.PrintStats(total, success, failed)
		}
	} else {
		// 如果是终端输出且不是安静模式，先打印统计信息
		if !quiet && total > 0 {
			ui.PrintStats(total, success, failed)
			fmt.Println()
		}
		fmt.Print(result)
	}
}

// linksToClash 将链接转换为 Clash 配置
func linksToClash(content string, mode string, quiet bool) (string, int, int, int, error) {
	proxies, errs := parser.ParseMultiple(content)

	total := len(proxies) + len(errs)
	success := len(proxies)
	failed := len(errs)

	if !quiet && len(errs) > 0 {
		for _, err := range errs {
			ui.PrintWarning(fmt.Sprintf("解析警告: %v", err))
		}
	}

	if len(proxies) == 0 {
		return "# 无有效节点\n# No valid nodes\n", total, success, failed, nil
	}

	// 转换模式
	var outputMode generator.ClashOutputMode
	switch strings.ToLower(mode) {
	case "payload":
		outputMode = generator.ModePayload
	case "none":
		outputMode = generator.ModeNone
	default:
		outputMode = generator.ModeProxies
	}

	result, err := generator.GenerateClash(proxies, outputMode)
	return result, total, success, failed, err
}

// clashToLinks 将 Clash 配置转换为链接
func clashToLinks(content string) (string, int, int, int, error) {
	proxies, err := parser.ParseClashYAML(content)
	if err != nil {
		return "", 0, 0, 0, err
	}

	total := len(proxies)
	if total == 0 {
		return "# 未检测到任何节点\n# No nodes found\n", 0, 0, 0, nil
	}

	uris := generator.GenerateURIs(proxies)
	success := len(uris)
	failed := total - success

	return strings.Join(uris, "\n") + "\n", total, success, failed, nil
}

// fetchURL 从 URL 获取内容
func fetchURL(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// readStdin 从标准输入读取
func readStdin() (string, error) {
	// 检查是否有管道输入
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		return "", nil
	}

	reader := bufio.NewReader(os.Stdin)
	var lines []string

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				if line != "" {
					lines = append(lines, line)
				}
				break
			}
			return "", err
		}
		lines = append(lines, line)
	}

	return strings.Join(lines, ""), nil
}
