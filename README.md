# astrbot_plugin_codebuddy

AstrBot 插件：接入腾讯 **CodeBuddy（中国版）** 的模型（DeepSeek V4 / GLM / Kimi 等），
无需任何 API Key——通过逆向 CodeBuddy 官方客户端的私有协议，用你自己的
CodeBuddy/腾讯云账号登录后，把模型暴露成一个**本地 OpenAI 兼容网关**，
AstrBot 原生 `OpenAI Compatible` 提供商即可使用。

> ⚠️ 本插件是"客户端模拟 + 私有接口逆向"，非腾讯官方 API：
> - 登录必须用你自己的 CodeBuddy/腾讯云账号，配额/额度记在该账号名下；
> - 端点、请求头、风控指纹可能随腾讯侧更新而失效；
> - 违反厂商服务条款的风险由使用者自行承担；仅供学习与个人用途。
>
> 协议逆向来源：[Ebony-Vinyl/dsh-our-free-model](https://github.com/Ebony-Vinyl/dsh-our-free-model)
> （MIT 许可，见 `codebuddy.py` 头部许可声明）。

## 安装（以 NAS + Docker 部署 AstrBot 为例）

### 1. 部署 AstrBot（Docker）

国内网络拉取官方镜像可能失败，使用 DaoCloud 国内镜像加速：

```bash
mkdir astrbot && cd astrbot
sudo docker run -itd \
  -p 6185:6185 -p 6199:6199 \
  -v $PWD/data:/AstrBot/data \
  -v /etc/localtime:/etc/localtime:ro \
  -v /etc/timezone:/etc/timezone:ro \
  --name astrbot \
  m.daocloud.io/docker.io/soulter/astrbot:latest
```

- 群晖用户：用套件中心安装 Docker（Container Manager）后在界面里跑上述命令，或直接用"项目/Compose"粘贴配置；
- 威联通/绿联/极空间同理（自带 Docker 或 Container Station / Docker 应用）；
- 部署后访问 `http://NAS_IP:6185`：首次登录默认账号 `admin` / 密码 `admin123456`（**务必在 WebUI 修改**）。

### 2. 安装插件

**方式 A（推荐，WebUI 从仓库安装）**：AstrBot WebUI →「插件」→「安装插件」→
填入本仓库地址 `https://github.com/ShiinaRuri/astrbot_plugin_codebuddy`，
或直接上传打包好的 `astrbot_plugin_codebuddy.zip`。

**方式 B（容器内直接放文件）**：把插件目录拷贝到 NAS 上挂载的
`$PWD/data/plugins/astrbot_plugin_codebuddy/`，然后在 WebUI 插件页点击「重载」。

插件目录需包含 `main.py`、`codebuddy.py`、`metadata.yaml`、`requirements.txt`、
`_conf_schema.json`、`LICENSE`。

插件启用后会自动在 **容器内** 的 `127.0.0.1:8326` 启动 OpenAI 兼容网关
（AstrBot 与插件同进程，直接访问，无需映射端口）。

### 3. 登录 CodeBuddy

在任意会话给机器人发指令（指令以机器人为前缀，如 `/cblogin`）：

| 指令 | 作用 |
|---|---|
| `/cblogin` | 发起登录，机器人返回登录链接；用电脑/手机在浏览器打开并登录（腾讯云账号扫码） |
| `/cbstatus` | 查看登录账号、token 过期时间、模型数量、网关地址与 Key |
| `/cbmodels` | 列出当前可用的模型 id |
| `/cbkey` | 显示本地网关的 Base URL 与 Key |
| `/cblogout` | 注销当前账号 |

登录时插件会在后台轮询（最长 5 分钟），完成后会主动推送「登录成功」。

### 4. 在 AstrBot 配置为对话模型

1. WebUI → 「模型提供商」→「对话」→ 新增 → **OpenAI Compatible**；
2. 填写：
   - **API Base URL**：`http://127.0.0.1:8326/v1`
   - **API Key**：插件自动生成的 Key（发 `/cbkey` 获取；端口/Key 也可在插件配置页 `_conf_schema.json` 调整）
3. 保存并获取模型 → 勾选启用想用的模型（如 `deepseek-v4-flash`、`glm-5.3`）；
4. 「配置文件」→「AI 配置」→「模型」→ 将对话模型设为刚才启用的 CodeBuddy 模型，保存。

之后机器人对话即走 CodeBuddy 通道。

## 实现说明 / 目录结构

```
astrbot_plugin_codebuddy/
├── main.py             # AstrBot 插件：指令 + 本地 OpenAI 兼容网关
├── codebuddy.py        # 核心库：轮询登录 / token 刷新 / 模型列表 / 流式对话 / 指纹改写
├── metadata.yaml       # AstrBot 插件元数据
├── requirements.txt    # 依赖：httpx
├── _conf_schema.json   # 插件配置项（端口/Key/默认模型）
├── LICENSE             # MIT（含上游第三方声明）
└── README.md
```

- 登录：`external-link-v2` 轮询（`POST /v2/plugin/auth/state` → 浏览器登录 → 轮询
  `GET /v2/plugin/auth/token` 与 `login/account`），服务器无需浏览器；
- 推理：`POST https://copilot.tencent.com/v2/chat/completions`（OpenAI 兼容 SSE），
  携带伪装的官方客户端头（`User-Agent=CodeBuddyIDE/1.106.1`、`X-Domain`、`X-Product-Code` 等）；
- 风控：对 system 消息做腾讯风控指纹改写（参照 upstream `tencent-fingerprint.ts`）；
- 凭据：存于 AstrBot `data/plugin_data/astrbot_plugin_codebuddy/credential.json`，权限 0600，
  浏览器/前端不可读；token 到期前自动用 refresh_token 静默续期。

## 已知限制与风险

- CodeBuddy 后端可能按出口 IP/账号做地区或治理风控（国内 NAS 出口为正规运营商线路，
  成功率明显高于海外服务器）；
- 模型列表、可用性以登录账号实际可见为准；
- 腾讯随时可能改变私有协议，届时插件需要同步更新；
- 请勿把账号用于商业转售/多用户共享等高危场景。

## License

MIT，见 [LICENSE](LICENSE)（其中包含上游第三方声明）。

协议逆向与关键实现参考了 [Ebony-Vinyl/dsh-our-free-model](https://github.com/Ebony-Vinyl/dsh-our-free-model)
（MIT, Copyright (c) 2026 Ebony-Vinyl），详见 `codebuddy.py` 头部许可声明。