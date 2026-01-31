# jmsc - JustMySocks to Clash 转换工具

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)

将 [JustMySocks](https://justmysocks.net/members/aff.php?aff=12439) 订阅地址转换为 Clash 配置文件的命令行工具。

**为什么需要离线转换？** 市面上大多数在线订阅转换服务需要你提交订阅链接，这意味着你的节点信息会经过第三方服务器，存在被记录或滥用的风险。jmsc 完全在本地运行，你的订阅数据不会离开你的设备。

> **jmsc** = **J**ust**M**y**S**ocks to **C**lash

## ✨ 功能特点

- 🔄 将 JustMySocks 订阅链接转换为 Clash YAML 配置
- 📦 支持 11 种代理协议（SS、VMess、VLESS、Trojan 等）
- 🖥️ 交互式命令行界面，操作简单
- 🔒 纯本地处理，**不上传任何数据**
- ⚡ 单文件二进制，无需安装依赖

## 📥 安装

### 从源码编译

```bash
git clone https://github.com/iswangwenbin/jmsc.git
cd jmsc
go build -o jmsc .
```

### 下载预编译版本

前往 [Releases](https://github.com/iswangwenbin/jmsc/releases) 页面下载对应平台的二进制文件。

## 🚀 使用方法

### 交互式模式（推荐）

直接运行 `jmsc`，按提示操作：

```bash
./jmsc
```

会引导你：
1. 选择输入来源（订阅 URL / 本地文件 / 粘贴链接）
2. 输入订阅地址
3. 确认保存文件路径

### 命令行模式

```bash
# 从订阅 URL 转换
./jmsc -u "https://your-subscription-url" -o clash.yaml

# 从文件转换
./jmsc -i links.txt -o clash.yaml

# 管道输入
cat links.txt | ./jmsc -o clash.yaml

# 直接转换链接
./jmsc "ss://..." "vmess://..."
```

### 命令行选项

| 选项 | 说明 |
|------|------|
| `-u, --url` | 订阅 URL |
| `-i, --input` | 输入文件路径 |
| `-o, --output` | 输出文件路径 |
| `-r, --reverse` | 反向转换: Clash → 链接 |
| `-q, --quiet` | 安静模式，只输出结果 |
| `-h, --help` | 显示帮助 |

## 📋 支持的协议

| 协议 | URI 前缀 | 状态 |
|------|----------|------|
| Shadowsocks | `ss://` | ✅ |
| ShadowsocksR | `ssr://` | ✅ |
| VMess | `vmess://` | ✅ |
| VLESS | `vless://` | ✅ |
| Trojan | `trojan://` | ✅ |
| Hysteria | `hysteria://`, `hy://` | ✅ |
| Hysteria2 | `hysteria2://`, `hy2://` | ✅ |
| TUIC | `tuic://` | ✅ |
| WireGuard | `wireguard://`, `wg://` | ✅ |
| HTTP | `http://`, `https://` | ✅ |
| SOCKS5 | `socks5://` | ✅ |

## 📁 项目结构

```
jmsc/
├── main.go                 # CLI 入口
├── go.mod
├── pkg/
│   ├── types/proxy.go      # 代理类型定义
│   ├── parser/             # 协议解析器
│   │   ├── parser.go       # 解析入口
│   │   ├── ss.go           # SS/SSR
│   │   ├── vmess.go        # VMess
│   │   ├── vless.go        # VLESS
│   │   ├── trojan.go       # Trojan
│   │   ├── hysteria.go     # Hysteria/Hysteria2
│   │   ├── others.go       # TUIC/WireGuard/HTTP/SOCKS5
│   │   └── clash.go        # Clash YAML 解析
│   ├── generator/          # 配置生成器
│   │   ├── clash.go        # 生成 Clash YAML
│   │   └── uri.go          # 生成分享链接
│   ├── ui/                 # 终端 UI
│   │   ├── styles.go       # 样式定义
│   │   └── interactive.go  # 交互式界面
│   └── utils/utils.go      # 工具函数
└── README.md
```

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 提交 Pull Request

## ⚠️ 免责声明

- 本工具仅提供格式转换功能，**不提供任何代理服务**
- 本工具**不存储、不上传**任何用户数据
- 请遵守当地法律法规使用本工具
- 使用本工具产生的一切后果由使用者自行承担

## 📜 许可证

本项目基于 [GPL-3.0](LICENSE) 许可证开源。
