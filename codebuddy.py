# -*- coding: utf-8 -*-
"""
CodeBuddy (腾讯中国版) 客户端核心库 —— 纯 Python，无 AstrBot 依赖。

这是把 dsh-our-free-model 逆向出的私有协议移植成 Python 的最小可用版。
上游协议来自：
    https://github.com/Ebony-Vinyl/dsh-our-free-model  (MIT License)
    具体文件：vendor/channel-pack/src/
        - buddy.ts           端点常量 / 凭据结构 / JWT 解析
        - buddy-oauth.ts     external-link-v2 轮询登录 / refresh / model list
        - buddy-adapter.ts   /v2/chat/completions 调用与 SSE 流解析
        - product.ts         产品配置（endpoint / UA / 归属头）
        - openai-gateway/tencent-fingerprint.ts  腾讯风控指纹改写

按 MIT 许可：保留上述版权与许可声明。协议端点 / 请求头可能随腾讯侧变更而失效，
使用后果自行承担。

设计目标：
  1. 服务器 headless 可跑 —— 登录是"设备码式轮询"，无需浏览器；
  2. 只依赖 httpx；
  3. 核心能力：登录 / token 刷新 / 模型列表 / 流式与非流式对话。
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator, Awaitable, Callable, Optional

import httpx

# ──────────────────────────────────────────────────────────────────────────
# 常量：逆向自 buddy.ts / product.ts（CodeBuddy 中国版）
# ──────────────────────────────────────────────────────────────────────────

API_ENDPOINT = "https://copilot.tencent.com"
API_DOMAIN = "copilot.tencent.com"
PLATFORM = "ide"                 # auth/state 的 platform 查询参数
PRODUCT_CODE = "codebuddy"      # X-Product-Code
USER_AGENT = "CodeBuddyIDE/1.106.1"
CLIENT_VERSION = "1.106.1"      # X-IDE-Version
ATTRIBUTION_NAME = "CodeBuddy"  # X-IDE-Name / X-IDE-Type / X-Product 归属名

# 端点路径
AUTH_STATE_PATH = "/v2/plugin/auth/state"
AUTH_TOKEN_PATH = "/v2/plugin/auth/token"
LOGIN_ACCOUNT_PATH = "/v2/plugin/login/account"
AUTH_REFRESH_PATH = "/v2/plugin/auth/token/refresh"
CONFIG_PATH = "/v3/config"
CHAT_COMPLETIONS_PATH = "/v2/chat/completions"
# 企业模型端点（比 /v3/config 更全，scope=personal 为个人账号）
SCOPED_MODELS_PATH = "/console/enterprises/personal/models"

# 轮询登录
LOGIN_TIMEOUT_MS = 5 * 60 * 1000   # 总超时 5 分钟
POLL_INTERVAL_MS = 1000            # 轮询间隔 1 秒
STATE_REQUEST_TIMEOUT_MS = 10_000  # auth/state 超时（较慢）
REQUEST_TIMEOUT_MS = 60_000        # 其余控制面超时

# 后端错误码：token / 账户尚未就绪 → 继续轮询
CODE_TOKEN_NOT_READY = 11217
CODE_ACCOUNT_NOT_READY = 12151

# 腾讯系内容级风控指纹（见 tencent-fingerprint.ts）：
# 网关对 system 文本做字面量级检测，命中即 400/11128 "Illegal API invocation"。
# 改写（非删除）语义等价句可放行。表驱动，便于后续追加。
CONTENT_FINGERPRINTS: list[dict[str, str]] = [
    {
        "find": "Main branch (you will usually use this for PRs)",
        "replace": "Main branch (PRs usually go here)",
    },
]

DEFAULT_CREDENTIAL_PATH = Path.home() / ".codebuddy-agent" / "credential.json"


# ──────────────────────────────────────────────────────────────────────────
# 数据结构
# ──────────────────────────────────────────────────────────────────────────

@dataclass
class Credential:
    access_token: str
    refresh_token: str = ""
    token_type: str = "Bearer"
    scope: str = ""
    domain: str = API_DOMAIN
    user_id: str = ""
    nickname: str = ""
    enterprise_id: str = ""
    account_type: str = "personal"
    expires_at_ms: int = 0        # access token 过期（毫秒时间戳）
    refresh_expires_at_ms: int = 0

    def expired(self, now_ms: Optional[int] = None) -> bool:
        if self.expires_at_ms <= 0:
            return False
        return (now_ms or int(time.time() * 1000)) >= self.expires_at_ms


@dataclass
class StreamEvent:
    """一次流式响应里交给调用方的事件。"""
    kind: str            # "content" | "reasoning" | "done" | "error"
    text: str = ""
    usage: dict = None   # type: ignore[assignment]


class CodeBuddyError(Exception):
    """CodeBuddy HTTP 层错误。"""
    def __init__(self, status: int, code: Any, message: str, body: str = ""):
        self.status = status
        self.code = code
        self.message = message
        self.body = body
        super().__init__(f"CodeBuddy HTTP {status} code={code}: {message}")


# ──────────────────────────────────────────────────────────────────────────
# 工具函数
# ──────────────────────────────────────────────────────────────────────────

def _b64url_decode(part: str) -> dict:
    """解码 JWT 的 payload 段（不验签，仅读声明）。"""
    pad = "=" * (-len(part) % 4)
    raw = base64.urlsafe_b64decode(part + pad)
    return json.loads(raw.decode("utf-8"))


def _jwt_payload(token: str) -> Optional[dict]:
    parts = token.split(".")
    if len(parts) < 2:
        return None
    try:
        return _b64url_decode(parts[1])
    except Exception:
        return None


def _jwt_claim_ms(token: str, keys: tuple[str, ...]) -> Optional[int]:
    payload = _jwt_payload(token)
    if not payload:
        return None
    for key in keys:
        value = payload.get(key)
        if isinstance(value, (int, float)):
            # exp/iat 是秒；数值可能已是毫秒
            if value > 10_000_000_000:
                return int(value)
            return int(value * 1000)
    return None


def _read_str(data: dict, key: str) -> str:
    value = data.get(key)
    if isinstance(value, str):
        return _strip_control(value)
    if isinstance(value, (int, float)):
        return str(value)
    return ""


def _strip_control(value: str) -> str:
    return re.sub(r"[\u0000-\u001f\u007f]+", " ", value).strip()


def _response_data(body: Any) -> Optional[dict]:
    if isinstance(body, dict):
        data = body.get("data")
        return data if isinstance(data, dict) else None
    return None


def _response_code(body: Any) -> int:
    if isinstance(body, dict):
        code = body.get("code")
        return code if isinstance(code, int) else 0
    return 0


def _error_message(body: Any) -> str:
    """腾讯系错误体：优先 displayMsg.zh，其次 msg / message / error.message。"""
    if not isinstance(body, dict):
        return str(body)
    display = body.get("displayMsg")
    if isinstance(display, dict):
        zh = display.get("zh")
        if zh:
            return zh
        en = display.get("en")
        if en:
            return en
    for key in ("msg", "message"):
        if body.get(key):
            return str(body[key])
    error = body.get("error")
    if isinstance(error, dict) and error.get("message"):
        return str(error["message"])
    return json.dumps(body, ensure_ascii=False)


def rewrite_system_fingerprints(text: str) -> str:
    """对 system 文本做窄改写（对齐 rewriteTencentContentFingerprints）。

    只改 system、不改 user/tool；大小写不敏感的**字面量**精确匹配，不做正则泛化。
    """
    for rule in CONTENT_FINGERPRINTS:
        find, replace = rule["find"], rule["replace"]
        if find.lower() in text.lower():
            text = re.sub(re.escape(find), replace, text, flags=re.IGNORECASE)
    return text


# ──────────────────────────────────────────────────────────────────────────
# 客户端
# ──────────────────────────────────────────────────────────────────────────

class CodeBuddyClient:
    def __init__(
        self,
        credential_path: Optional[Path] = None,
        user_agent: str = USER_AGENT,
        timeout: float = 120.0,
    ):
        self.credential_path = Path(credential_path) if credential_path else DEFAULT_CREDENTIAL_PATH
        self.user_agent = user_agent
        self._credential: Optional[Credential] = self._load_credential()
        self._http = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout, connect=10.0),
            follow_redirects=True,
        )

    # ── 凭据持久化 ────────────────────────────────────────────────────────

    def _load_credential(self) -> Optional[Credential]:
        try:
            data = json.loads(self.credential_path.read_text(encoding="utf-8"))
            cred = Credential(**{k: data.get(k, v) for k, v in Credential().__dict__.items()})
            if not cred.access_token:
                return None
            return cred
        except Exception:
            return None

    def _save_credential(self, cred: Credential) -> None:
        self.credential_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.credential_path.with_suffix(".tmp")
        data = cred.__dict__.copy()
        tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(self.credential_path)

    # ── 基础请求头 ────────────────────────────────────────────────────────

    def _base_headers(self) -> dict[str, str]:
        return {
            "X-Domain": API_DOMAIN,
            "User-Agent": self.user_agent,
        }

    def _auth_headers(self, cred: Credential) -> dict[str, str]:
        headers = self._base_headers()
        headers["Authorization"] = f"Bearer {cred.access_token}"
        if cred.enterprise_id:
            headers["X-Enterprise-Id"] = cred.enterprise_id
            headers["X-Tenant-Id"] = cred.enterprise_id
        return headers

    def _chat_headers(self, cred: Credential) -> dict[str, str]:
        """推理请求头：认证 + 归属标识。

        归属头（X-IDE-* / X-Product / X-Product-Code）用于腾讯后台"使用端"归因；
        缺失通常也能通，但后台用量会归因不明。按 product.ts 语义按产品名下发。
        """
        headers = self._auth_headers(cred)
        headers.update({
            "X-Product-Code": PRODUCT_CODE,
            "X-Product": ATTRIBUTION_NAME,   # 注意：历史上曾误发为 "SaaS"
            "X-IDE-Name": ATTRIBUTION_NAME,
            "X-IDE-Type": ATTRIBUTION_NAME,
            "X-IDE-Version": CLIENT_VERSION,
        })
        return headers

    # ── 登录（external-link-v2 轮询式） ───────────────────────────────────

    async def start_login(self) -> tuple[str, str]:
        """第一步：发起登录，返回 (state, auth_url)。

        headless / 聊天机器人场景：把 auth_url 发给用户打开，然后把 state
        交给 finish_login() 在后台轮询，等待用户完成登录。
        """
        r = await self._http.post(
            f"{API_ENDPOINT}{AUTH_STATE_PATH}",
            params={"platform": PLATFORM},
            headers={
                "X-Domain": API_DOMAIN,
                "X-No-Authorization": "true",
                "X-No-User-Id": "true",
                "X-No-Enterprise-Id": "true",
                "X-No-Department-Info": "true",
                "User-Agent": self.user_agent,
            },
            timeout=STATE_REQUEST_TIMEOUT_MS / 1000,
        )
        if r.status_code != 200:
            raise CodeBuddyError(r.status_code, 0, _error_message(_json_or(r)), r.text)
        data = _response_data(_json_or(r))
        if not data or not data.get("state"):
            raise CodeBuddyError(r.status_code, 0, f"auth/state 响应缺少 state: {r.text[:500]}", r.text)
        return data["state"], data.get("authUrl", "")

    async def finish_login(
        self,
        state: str,
        timeout_ms: int = LOGIN_TIMEOUT_MS,
        poll_interval_ms: int = POLL_INTERVAL_MS,
    ) -> Credential:
        """第二步：轮询等待用户完成登录，保存凭据并返回。适合放后台任务。"""
        token = await self._poll_token(state, timeout_ms, poll_interval_ms)
        account = await self._poll_account(state, token, timeout_ms, poll_interval_ms)
        cred = self._build_credential(token, account)
        self._credential = cred
        self._save_credential(cred)
        return cred

    async def login(
        self,
        on_auth_url: Optional[Callable[[str], Awaitable[None]]] = None,
        timeout_ms: int = LOGIN_TIMEOUT_MS,
        poll_interval_ms: int = POLL_INTERVAL_MS,
    ) -> Credential:
        """完整登录流程（阻塞式等待）。

        headless 环境建议改用 start_login() + finish_login() 异步组合；
        on_auth_url 仅用于把登录 URL 交到别处（如 QQ），未提供时打印到 stdout。
        """
        state, auth_url = await self.start_login()
        if on_auth_url is not None:
            await on_auth_url(auth_url)
        else:
            print("\n请打开以下链接完成登录（扫码 / 账号密码），登录完成后程序会自动继续：\n")
            print("  " + auth_url + "\n")
        return await self.finish_login(state, timeout_ms, poll_interval_ms)

    def logout(self) -> None:
        """清除本地凭据（下次调用前需重新登录）。"""
        self._credential = None
        try:
            self.credential_path.unlink(missing_ok=True)
        except Exception:
            pass

    async def _poll_token(self, state: str, timeout_ms: int, poll_ms: int) -> dict:
        url = f"{API_ENDPOINT}{AUTH_TOKEN_PATH}"
        deadline = time.monotonic() + timeout_ms / 1000
        while True:
            if time.monotonic() >= deadline:
                raise CodeBuddyError(0, 0, "获取 token 超时（5 分钟）")
            await asyncio.sleep(poll_ms / 1000)
            try:
                r = await self._http.get(
                    url,
                    params={"state": state},
                    headers={"X-No-Authorization": "true", "User-Agent": self.user_agent},
                    timeout=REQUEST_TIMEOUT_MS / 1000,
                )
            except httpx.HTTPError:
                continue  # 网络错误继续轮询（对齐 Rust loop_get_token）
            body = _json_or(r)
            if r.status_code == 200:
                data = _response_data(body)
                if data is not None:
                    return data
                continue
            if _response_code(body) == CODE_TOKEN_NOT_READY:
                continue
            raise CodeBuddyError(r.status_code, _response_code(body), _error_message(body), r.text)

    async def _poll_account(self, state: str, token: dict, timeout_ms: int, poll_ms: int) -> dict:
        domain = _read_str(token, "domain") or API_DOMAIN
        url = f"{API_ENDPOINT}{LOGIN_ACCOUNT_PATH}"
        deadline = time.monotonic() + timeout_ms / 1000
        while True:
            if time.monotonic() >= deadline:
                raise CodeBuddyError(0, 0, "获取账户信息超时（5 分钟）")
            await asyncio.sleep(poll_ms / 1000)
            headers = {
                "X-Domain": domain,
                "Authorization": f"Bearer {_read_str(token, 'accessToken')}",
                "X-No-User-Id": "true",
                "X-No-Enterprise-Id": "true",
                "User-Agent": self.user_agent,
            }
            try:
                r = await self._http.get(url, params={"state": state}, headers=headers,
                                         timeout=REQUEST_TIMEOUT_MS / 1000)
            except httpx.HTTPError:
                continue
            body = _json_or(r)
            if r.status_code == 200:
                data = _response_data(body)
                if data is not None:
                    return data
                continue
            if _response_code(body) == CODE_ACCOUNT_NOT_READY:
                continue
            raise CodeBuddyError(r.status_code, _response_code(body), _error_message(body), r.text)

    def _build_credential(self, token: dict, account: dict) -> Credential:
        access_token = _read_str(token, "accessToken")
        expires_at_ms = self._expiry_ms(token, access_token, "expiresAt", "expiresIn")
        refresh_expires_at_ms = self._expiry_ms(token, access_token, "refreshExpiresAt", "refreshExpiresIn")

        # 昵称：account.nickname 常为空，回退 JWT 声明
        nickname = _read_str(account, "nickname")
        if not nickname:
            payload = _jwt_payload(access_token) or {}
            nickname = str(payload.get("nickname") or payload.get("preferred_username") or payload.get("name") or "")
        user_id = _read_str(account, "uid")
        if not user_id:
            payload = _jwt_payload(access_token) or {}
            user_id = str(payload.get("sub") or "")

        return Credential(
            access_token=access_token,
            refresh_token=_read_str(token, "refreshToken"),
            token_type=_read_str(token, "tokenType") or "Bearer",
            scope=_read_str(token, "scope"),
            domain=_read_str(token, "domain") or API_DOMAIN,
            user_id=user_id,
            nickname=nickname,
            enterprise_id=_read_str(account, "enterpriseId"),
            account_type=_read_str(account, "type") or "personal",
            expires_at_ms=expires_at_ms,
            refresh_expires_at_ms=refresh_expires_at_ms,
        )

    @staticmethod
    def _expiry_ms(token: dict, access_token: str,
                   absolute_key: str, relative_key: str) -> int:
        """auth/token 只返回相对秒数（expiresIn），无绝对 expiresAt；按 JWT 兜底换算。

        相对值以 access_token 的 iat（签发时刻）为基准（对齐上游 absoluteExpiryMs）。
        """
        absolute = _read_str(token, absolute_key)
        if absolute:
            value = int(float(absolute))
            return value if value > 10_000_000_000 else value * 1000
        relative = token.get(relative_key)
        if isinstance(relative, (int, float)):
            base = _jwt_claim_ms(access_token, ("iat",)) or int(time.time() * 1000)
            return base + int(relative * 1000)
        # 无相对值：用 JWT exp 兜底
        exp = _jwt_claim_ms(access_token, ("exp",))
        return exp or 0

    # ── token 续期 ────────────────────────────────────────────────────────

    async def refresh(self) -> Credential:
        if not self._credential or not self._credential.refresh_token:
            raise CodeBuddyError(0, 0, "无 refresh_token，请重新登录")
        cred = self._credential
        r = await self._http.post(
            f"{API_ENDPOINT}{AUTH_REFRESH_PATH}",
            headers={
                "X-Domain": API_DOMAIN,
                "User-Agent": self.user_agent,
                "Authorization": f"Bearer {cred.access_token}",
                "X-Refresh-Token": cred.refresh_token,
                "X-Auth-Refresh-Source": "ide-main",
            },
            timeout=REQUEST_TIMEOUT_MS / 1000,
        )
        body = _json_or(r)
        if r.status_code != 200:
            raise CodeBuddyError(r.status_code, _response_code(body), _error_message(body), r.text)
        data = _response_data(body)
        if data is None:
            raise CodeBuddyError(r.status_code, 0, "刷新响应缺少 data 字段", r.text)
        new_cred = self._build_credential(data, {
            "uid": cred.user_id, "nickname": cred.nickname,
            "enterpriseId": cred.enterprise_id, "type": cred.account_type,
        })
        if not new_cred.refresh_token:
            new_cred.refresh_token = cred.refresh_token
        self._credential = new_cred
        self._save_credential(new_cred)
        return new_cred

    async def _ensure_valid(self) -> Credential:
        if self._credential is None:
            raise CodeBuddyError(0, 0, "未登录，请先调用 login()")
        if self._credential.expired():
            await self.refresh()
        return self._credential

    # ── 模型列表 ──────────────────────────────────────────────────────────

    async def list_models(self) -> list[dict]:
        """返回可用对话模型列表。优先企业模型端点，回退 /v3/config。"""
        cred = await self._ensure_valid()
        headers = self._auth_headers(cred)
        headers.update({
            "X-Product-Code": PRODUCT_CODE,
            "X-Product": ATTRIBUTION_NAME,
        })
        # 1) 企业模型端点（scope=personal）
        try:
            r = await self._http.get(f"{API_ENDPOINT}{SCOPED_MODELS_PATH}", headers=headers,
                                     timeout=REQUEST_TIMEOUT_MS / 1000)
            if r.status_code == 200:
                models = self._parse_models(_json_or(r))
                if models:
                    return models
        except httpx.HTTPError:
            pass
        # 2) /v3/config
        r = await self._http.get(f"{API_ENDPOINT}{CONFIG_PATH}", headers=headers,
                                 timeout=REQUEST_TIMEOUT_MS / 1000)
        if r.status_code != 200:
            raise CodeBuddyError(r.status_code, _response_code(_json_or(r)),
                                 _error_message(_json_or(r)), r.text)
        return self._parse_models(_json_or(r))

    @staticmethod
    def _parse_models(body: Any) -> list[dict]:
        data = body.get("data") if isinstance(body, dict) else None
        if not isinstance(data, dict):
            return []
        meta_by_id: dict[str, dict] = {}
        for model in data.get("models", []) or []:
            if isinstance(model, dict) and isinstance(model.get("id"), str):
                meta_by_id[model["id"]] = model

        agent_ids: list[str] = []
        for agent in data.get("agents", []) or []:
            if isinstance(agent, dict) and agent.get("name") in ("craft", "cli"):
                agent_ids = [m for m in agent.get("models", []) if isinstance(m, str)]
                break

        ordered_ids: list[str] = []
        for mid in agent_ids + list(meta_by_id.keys()):
            if mid not in ordered_ids:
                ordered_ids.append(mid)

        def _is_chat(model_id: str, meta: Optional[dict]) -> bool:
            if model_id in ("auto", "default"):
                return False
            if model_id.startswith(("nes-", "completion-", "codewise-")):
                return False
            if meta and meta.get("supportsExtra") is True:
                return False
            if meta:
                max_out = meta.get("maxOutputTokens")
                if isinstance(max_out, (int, float)) and 0 < int(max_out) <= 256:
                    return False
                tags = meta.get("tags")
                if isinstance(tags, list) and "text-to-image" in tags:
                    return False
            return True

        result: list[dict] = []
        for mid in ordered_ids:
            meta = meta_by_id.get(mid)
            if not _is_chat(mid, meta):
                continue
            entry: dict[str, Any] = {
                "id": mid,
                "name": (meta or {}).get("name") or mid,
            }
            if meta:
                for key in ("maxInputTokens", "maxOutputTokens", "supportsImages", "credits"):
                    if key in meta:
                        entry[key] = meta[key]
                reasoning = meta.get("reasoning")
                if isinstance(reasoning, dict):
                    entry["reasoning"] = reasoning
            result.append(entry)
        return result

    # ── 对话 ──────────────────────────────────────────────────────────────

    async def stream_chat(
        self,
        messages: list[dict],
        model: str,
        *,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        reasoning_effort: Optional[str] = None,
    ) -> AsyncIterator[StreamEvent]:
        """流式对话，逐帧产出 StreamEvent（content / reasoning / done / error）。"""
        cred = await self._ensure_valid()
        wire_messages = self._serialize_messages(messages)
        payload: dict[str, Any] = {"model": model, "messages": wire_messages, "stream": True}
        if max_tokens:
            payload["max_tokens"] = max_tokens
        if temperature is not None:
            payload["temperature"] = temperature
        # DeepSeek 系模型开思考需显式 thinking + reasoning_effort；其余模型忽略。
        if reasoning_effort and re.match(r"^deepseek", model, re.IGNORECASE):
            payload["thinking"] = {"type": "enabled"}
            payload["reasoning_effort"] = reasoning_effort

        headers = self._chat_headers(cred)
        async with self._http.stream("POST", f"{API_ENDPOINT}{CHAT_COMPLETIONS_PATH}",
                                     json=payload, headers=headers) as resp:
            if resp.status_code != 200:
                text = (await resp.aread()).decode("utf-8", "replace")
                body = _json_or_text(text)
                yield StreamEvent("error", text=_error_message(body))
                return
            buffer = ""
            async for chunk in resp.aiter_bytes():
                buffer += chunk.decode("utf-8", "replace")
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    line = line.strip()
                    if not line.startswith("data:"):
                        continue
                    payload_text = line[5:].strip()
                    if payload_text == "[DONE]":
                        yield StreamEvent("done")
                        return
                    try:
                        frame = json.loads(payload_text)
                    except json.JSONDecodeError:
                        continue
                    # 流内错误帧（HTTP 200 + SSE 内嵌 code/msg，无 choices）
                    if isinstance(frame, dict) and frame.get("choices") is None:
                        code = frame.get("code")
                        if code is not None:
                            yield StreamEvent("error", text=_error_message(frame))
                            return
                        continue
                    choices = frame.get("choices") or []
                    if not choices:
                        continue
                    delta = (choices[0].get("delta") or {})
                    if delta.get("content"):
                        yield StreamEvent("content", text=delta["content"])
                    if delta.get("reasoning_content"):
                        yield StreamEvent("reasoning", text=delta["reasoning_content"])
                    # usage 帧忽略：聊天机器人无需 token 记账；结束统一以 [DONE] 为准

    @staticmethod
    def _serialize_messages(messages: list[dict]) -> list[dict]:
        """把消息规整为 OpenAI Chat Completions 形态，并对 system 做风控指纹改写。

        assistant 消息若复数块以 list 传入时此处不做深加工——聊天机器人一般传
        纯文本即可。支持 content 为 str 或 OpenAI 多模态 parts list。
        """
        wire: list[dict] = []
        for msg in messages:
            role = msg.get("role")
            content = msg.get("content")
            if role == "system":
                text = content if isinstance(content, str) else "".join(
                    p.get("text", "") for p in content if isinstance(p, dict)
                )
                wire.append({"role": "system", "content": rewrite_system_fingerprints(text)})
            else:
                wire.append({"role": role, "content": content})
        return wire

    async def chat(
        self,
        messages: list[dict],
        model: str,
        *,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        reasoning_effort: Optional[str] = None,
    ) -> str:
        """非流式对话：聚合 stream_chat 的正文，返回纯文本。"""
        parts: list[str] = []
        async for event in self.stream_chat(
            messages, model, max_tokens=max_tokens,
            temperature=temperature, reasoning_effort=reasoning_effort,
        ):
            if event.kind == "content":
                parts.append(event.text)
            elif event.kind == "error":
                raise CodeBuddyError(0, 0, event.text)
        return "".join(parts)

    async def aclose(self) -> None:
        await self._http.aclose()


# ──────────────────────────────────────────────────────────────────────────
# 工具
# ──────────────────────────────────────────────────────────────────────────

def _json_or(r: httpx.Response) -> Any:
    try:
        return r.json()
    except Exception:
        return {}


def _json_or_text(text: str) -> Any:
    try:
        return json.loads(text)
    except Exception:
        return {"msg": text[:500]}


# ──────────────────────────────────────────────────────────────────────────
# CLI 演示
# ──────────────────────────────────────────────────────────────────────────

async def _demo() -> None:
    client = CodeBuddyClient()
    try:
        # 已登录则跳过；否则走登录流程
        if not client._credential:
            await client.login()

        print("获取模型列表…")
        try:
            models = await client.list_models()
        except CodeBuddyError as e:
            print(f"\n[获取模型失败] {e}")
            print("提示：若为 HTTP 403 / region 相关，多为甲骨文出口 IP 被腾讯网关按地区拦截；")
            print("      可尝试更换服务器区域，或改用海外渠道（www.workbuddy.ai）。")
            return
        if not models:
            print("未获取到模型（可能账号/地区受限，或 token 拿不到完整模型池）")
            return
        print("可用模型：")
        for m in models[:30]:
            print(f"  - {m['id']:30s}  {m.get('name', '')}")

        model = models[0]["id"]
        print(f"\n使用模型 {model} 对话（输入 quit 退出）：")
        history: list[dict] = [{"role": "system", "content": "You are a helpful assistant."}]
        while True:
            user_input = await asyncio.get_event_loop().run_in_executor(None, input, "你: ")
            if user_input.strip().lower() in ("quit", "exit", "q"):
                break
            history.append({"role": "user", "content": user_input})
            reply_parts: list[str] = []
            print("助手: ", end="", flush=True)
            async for event in client.stream_chat(history, model):
                if event.kind == "content":
                    reply_parts.append(event.text)
                    print(event.text, end="", flush=True)
                elif event.kind == "error":
                    print(f"\n[错误] {event.text}")
            print()
            history.append({"role": "assistant", "content": "".join(reply_parts)})
    finally:
        await client.aclose()


if __name__ == "__main__":
    try:
        asyncio.run(_demo())
    except KeyboardInterrupt:
        pass