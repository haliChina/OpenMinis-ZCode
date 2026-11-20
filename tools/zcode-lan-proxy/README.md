# ZCode 局域网代理

把一个 ZCode 账号的套餐网关（Anthropic 格式的对话接口）暴露给局域网内的其他客户端使用。代理本体是一个零依赖的 Python 3 脚本，只用标准库，Windows、Linux、macOS 和 Termux 都能直接跑。

它做的事情：

- 用与官方客户端、与本仓库 Android 版相同的 CLI init/poll OAuth 流程登录一次，拿到 ZCode JWT；
- 在局域网里提供一个 Anthropic 兼容端点（`/v1/messages`、`/v1/models`），把请求补齐官方身份 system 块、全套客户端身份头和 `metadata.user_id` 后转发到 `https://zcode.z.ai/api/v1/zcode-plan/anthropic/v1/messages`；
- 流式响应逐块透传；全局并发上限 2（上游的单账号上限），超出的请求排队等待；
- 除 `/health` 外，所有请求都必须带代理自己的访问口令（access key），与 ZCode 账号无关，是代理这一层单独的门禁。

## 快速开始

需要 Python 3.8 以上，不需要 pip 安装任何东西。

```bash
cd tools/zcode-lan-proxy

# 1. 登录（只需一次；--provider bigmodel 可改用 BigModel 账号登录）
python3 zcode_proxy.py login

# 2. 启动代理（默认 0.0.0.0:8799）
python3 zcode_proxy.py serve
```

`login` 会打印一个授权链接，在浏览器里打开并完成授权，脚本轮询到结果后把配置写到脚本同目录的 `zcode-proxy-config.json`（权限 0600）。配置里有四项：`jwt`、`device_mid`、`user_id`、`access_key`。其中 `access_key` 是首次生成时随机产生的，只打印一次，请记好；之后每次 `serve` 都用它鉴权。重新 `login` 不会更换已有的 `device_mid` 和 `access_key`，只刷新 JWT。

改端口：`python3 zcode_proxy.py serve --port 9000`。

配置文件也可以放到仓库外（推荐）：`login` 和 `serve` 都支持 `--config /path/to/config.json`，路径保持一致即可。

## 客户端配置

把 `<局域网IP>` 换成运行代理那台机器的局域网地址（例如 `192.168.1.10`），`<access_key>` 换成登录时打印的口令。

### Claude Code

```bash
export ANTHROPIC_BASE_URL=http://<局域网IP>:8799
export ANTHROPIC_API_KEY=<access_key>
claude
```

模型用 Start Plan 的三个：`glm-5.3-flash`、`glm-5.2`、`glm-5-turbo`（大小写无所谓，代理会转成上游要的小写形式）。注意 Start Plan 没有 GLM-5.3，且只有 GLM-5.3-Flash 支持图片输入。

### OpenCode

`opencode.json`：

```json
{
  "$schema": "https://opencode.ai/config.json",
  "provider": {
    "zcode-lan": {
      "npm": "@ai-sdk/anthropic",
      "name": "ZCode (LAN)",
      "options": {
        "baseURL": "http://<局域网IP>:8799/v1",
        "apiKey": "<access_key>"
      },
      "models": {
        "glm-5.3-flash": { "name": "GLM-5.3-Flash" },
        "glm-5.2": { "name": "GLM-5.2" },
        "glm-5-turbo": { "name": "GLM-5-Turbo" }
      }
    }
  }
}
```

其他 Anthropic 兼容客户端同理：base URL 填 `http://<局域网IP>:8799`，API key 填 access key。健康检查端点 `GET /health` 免鉴权，返回 `{"ok": true}`。

## 行为说明

- 转发时 model 名转小写；`system` 最前面拼入官方 ZCode 身份块（3 段，与官方客户端一致），客户端自带的 system 保留在身份块之后；`metadata.user_id` 从 JWT 里解析填入。
- 平台、系统版本、语言、时区等身份头按代理实际运行的机器如实生成，不冒充手机。
- 上游的响应状态码和内容原样透传，包括错误。遇到验证码挑战（业务码 3007）代理无法处理，只会在日志里注明并原样返回，不重试——这种情况请回官方客户端或本仓库的 Android 版里处理。
- 请求体上限 32MB，超过返回 413。
- 日志只记录时间、方法、路径、模型、状态码和耗时，不记录 JWT、access key 和消息内容。
- JWT 过期后没有刷新机制（官方就没有），重新跑一次 `login` 即可。

## 自测

```bash
python3 test_zcode_proxy.py
```

会起一个本地假上游和代理本体，验证鉴权、身份头、system 块原文、model 小写、metadata、流式逐块到达、并发排队和 3007 透传，全部断言通过才以 0 退出。

## 风险提示

- **封号风险**：这类代理转发不是官方支持的用法，Z.ai 可能据其服务条款封停账号或回收套餐。额度多贵、账号多重要，自己权衡后再用。
- **额度共享**：所有经代理的请求都消耗同一个账号的套餐额度，并发上限也是全账号共享的 2。局域网里谁拿到 access key，谁就能用这个账号的额度。
- **配置文件是活凭据**：`zcode-proxy-config.json` 里是可直接使用的 JWT，不要外传、不要截图发人、不要提交进 git。本仓库的 `.gitignore` 已忽略这个文件名；更稳妥的做法是用 `--config` 把它放到仓库目录之外，并注意文件权限（脚本会设为 0600，Windows 上请自行确认）。
- 只在可信的局域网里开这个服务，不要把端口映射到公网。
