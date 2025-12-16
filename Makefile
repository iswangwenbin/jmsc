# jmsc Makefile
# 交叉编译不同平台的二进制文件

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)

# 输出目录
DIST_DIR := dist

# 支持的平台
PLATFORMS := \
	darwin/amd64 \
	darwin/arm64 \
	linux/amd64 \
	linux/arm64 \
	windows/amd64 \
	windows/arm64

.PHONY: all clean build release $(PLATFORMS)

# 默认构建当前平台
all: build

build:
	go build -ldflags "$(LDFLAGS)" -o jmsc .

# 清理构建产物
clean:
	rm -rf $(DIST_DIR)
	rm -f jmsc jmsc.exe

# 构建所有平台
release: clean $(PLATFORMS)
	@echo "✅ 所有平台构建完成!"
	@ls -la $(DIST_DIR)/

# 为每个平台构建
$(PLATFORMS):
	$(eval GOOS := $(word 1,$(subst /, ,$@)))
	$(eval GOARCH := $(word 2,$(subst /, ,$@)))
	$(eval EXT := $(if $(filter windows,$(GOOS)),.exe,))
	$(eval OUTPUT := $(DIST_DIR)/jmsc-$(GOOS)-$(GOARCH)$(EXT))
	@echo "🔨 构建 $(GOOS)/$(GOARCH)..."
	@mkdir -p $(DIST_DIR)
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(OUTPUT) .

# 创建压缩包 (用于发布)
package: release
	@echo "📦 创建发布包..."
	@cd $(DIST_DIR) && \
	for f in jmsc-*; do \
		if [ -f "$$f" ]; then \
			case "$$f" in \
				*.exe) zip "$${f%.exe}.zip" "$$f" ;; \
				*) tar -czf "$$f.tar.gz" "$$f" ;; \
			esac \
		fi \
	done
	@echo "✅ 发布包创建完成!"
	@ls -la $(DIST_DIR)/*.tar.gz $(DIST_DIR)/*.zip 2>/dev/null || true

# 安装到本地
install: build
	cp jmsc $(GOPATH)/bin/ 2>/dev/null || cp jmsc /usr/local/bin/

# 运行测试
test:
	go test -v ./...

# 检查代码
lint:
	golangci-lint run

.DEFAULT_GOAL := build
