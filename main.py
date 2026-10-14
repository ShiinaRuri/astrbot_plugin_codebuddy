# -*- coding: utf-8 -*-
"""
AstrBot 插件：腾讯 CodeBuddy（中国版）免费模型接入。

做法：复用逆向 CodeBuddy 官方客户端私有协议的核心库（codebuddy.py），
在本插件进程内起一个本地 OpenAI 兼容网关（默认 127.0.0.1:8326）。
AstrBot 自身在 WebUI 里新增一个 "OpenAI Compatible" 提供商指向该网关即可
把 CodeBuddy 的模型作为机器人的对话模型使用。

登录走 external-link-v2 轮询：/cblogin 把登录链接发到聊天，用户在浏览器
完成扫码/账号登录，插件后台轮询拿 token 并保存（存 AstrBot data 目录，
权限 0600）。

遵从 AstrBot 插件规范：继承 Star、@filter.command、yield event.plain_result、
后台任务用 self.context.send_message(umo, chain) 主动推送、use aiohttp/httpx。

协议逆向来源：https://github.com/Ebony-Vinyl/dsh-our-free-model (MIT License)
  vendor/channel-pack/src/buddy*.ts / product.ts
  （见本插件 codebuddy.py 头部注释的许可声明）
"""

import asyncio
import json
import secrets
import time
from typing import Any, Optional

from aiohttp import web

from astrbot.api import logger
from astrbot.api.event import AstrMessageEvent, MessageChain, filter
from astrbot.api.star import Context, Star

# AstrBot 以包路径导入插件（data.plugins.<插件名>.main），此时相对导入才有效；
# 但也兼容把插件目录直接加入 sys.path 的加载方式。
try:
    from .codebuddy import CodeBuddyClient, CodeBuddyError
except ImportError:  # pragma: no cover - 兼容非包导入
    from codebuddy import CodeBuddyClient, CodeBuddyError

DEFAULT_PORT = 8326
MODEL_CACHE_TTL = 30 * 60  # 模型列表缓存 30 分钟


class CodeBuddyPlugin(Star):
    def __init__(self, context: Context, config: dict = None):
        super().__init__(context)
        config = config or {}

        self.port = int(config.get("local_port") or DEFAULT_PORT)
        # 本地网关 Key：优先配置项；为空则首次启动自动生成并持久化
        self.local_key = str(config.get("local_key") or "").strip()
        if not self.local_key:
            self.local_key = self._load_or_create_key()
        self.default_model = str(config.get("default_model") or "").strip()

        self.client = CodeBuddyClient(credential_path=self._credential_path())
        self._models: list[dict] = []
        self._models_ts: float = 0.0
        self._pending_login: dict[str, str] = {}  # state -> unified_msg_origin
        self._gateway_runner: Optional[web.AppRunner] = None

        # AstrBot 基于 aiohttp，插件加载时通常已在事件循环内；做兼容回退
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.get_event_loop()
        loop.create_task(self._start_gateway())

    # ── 路径与 Key 管理 ──────────────────────────────────────────────────

    def _data_dir(self):
        """插件数据目录：AstrBot 官方的 data/plugin_data/<插件名>/。

        用官方 API get_astrbot_plugin_data_path()（v4.17.0+ 可用），
        避免自行拼接路径在后续版本中失配。
        """
        from pathlib import Path

        from astrbot.core.utils.astrbot_path import get_astrbot_plugin_data_path

        base = Path(get_astrbot_plugin_data_path()) / "astrbot_plugin_codebuddy"
        base.mkdir(parents=True, exist_ok=True)
        return base

    def _credential_path(self):
        """凭据文件路径（0600 权限，由 CodeBuddyClient 写入时设置）。"""
        return self._data_dir() / "credential.json"

    def _key_path(self):
        """本地网关 Key 的持久化路径。"""
        return self._data_dir() / "local_key.txt"

    def _load_or_create_key(self) -> str:
        path = self._key_path()
        try:
            key = path.read_text(encoding="utf-8").strip()
            if key:
                return key
        except Exception:
            pass
        key = "cb-" + secrets.token_hex(16)
        try:
            path.write_text(key, encoding="utf-8")
        except Exception as e:
            logger.warning(f"[CodeBuddy] 写入本地 Key 失败: {e}")
        return key

    # ── 指令 ─────────────────────────────────────────────────────────────

    @filter.command("cblogin")
    async def cblogin(self, event: AstrMessageEvent):
        """发起 CodeBuddy 登录：/cblogin"""
        if self.client._credential is not None:
            yield event.plain_result("已经登录了 CodeBuddy。需要重新登录请先发 /cblogout。")
            return
        try:
            state, auth_url = await self.client.start_login()
        except CodeBuddyError as e:
            yield event.plain_result(f"发起登录失败：{e}\n（若是网络错误，请检查 NAS 是否能直连 copilot.tencent.com）")
            return
        umo = event.unified_msg_origin
        self._pending_login[state] = umo
        yield event.plain_result(
            "请在 5 分钟内用电脑或手机打开下面的链接完成 CodeBuddy 登录"
            "（腾讯云账号 / 扫码），我会自动检测并确认：\n\n" + auth_url
        )
        loop = asyncio.get_running_loop()
        loop.create_task(self._wait_login(state, umo))

    async def _wait_login(self, state: str, umo: str):
        try:
            cred = await self.client.finish_login(state)
            text = f"CodeBuddy 登录成功（{cred.nickname or cred.user_id}）\n" \
                   f"现在可以在 WebUI 的『模型提供商』里测试/使用 CodeBuddy 模型了。"
        except CodeBuddyError as e:
            text = f"CodeBuddy 登录失败：{e}"
        except Exception as e:  # noqa: BLE001
            text = f"CodeBuddy 登录失败（异常）：{e}"
        finally:
            self._pending_login.pop(state, None)
        try:
            await self.context.send_message(umo, MessageChain().message(text))
        except Exception as e:  # noqa: BLE001
            logger.error(f"[CodeBuddy] 主动推送登录结果失败: {e}")

    @filter.command("cbstatus")
    async def cbstatus(self, event: AstrMessageEvent):
        """查看登录状态与本地网关信息：/cbstatus"""
        cred = self.client._credential
        lines = []
        if cred is None:
            lines.append("未登录。发送 /cblogin 发起登录。")
        else:
            who = cred.nickname or cred.user_id or "(未知用户)"
            lines.append(f"账号：{who}")
            if cred.expires_at_ms:
                exp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(cred.expires_at_ms / 1000))
                lines.append(f"Token 过期：{exp}（到期前自动刷新）")
            try:
                models = await self._get_models()
                lines.append(f"可用模型：{len(models)} 个（/cbmodels 查看清单）")
            except Exception as e:  # noqa: BLE001
                lines.append(f"模型列表拉取失败：{e}")
        lines.append(f"本地网关：http://127.0.0.1:{self.port}/v1")
        lines.append(f"网关 Key：{self.local_key}")
        yield event.plain_result("\n".join(lines))

    @filter.command("cbmodels")
    async def cbmodels(self, event: AstrMessageEvent):
        """列出当前可用的 CodeBuddy 模型：/cbmodels"""
        try:
            models = await self._get_models()
        except CodeBuddyError as e:
            yield event.plain_result(f"获取模型失败：{e}\n（可能账号未登录或已被风控/地区限制）")
            return
        if not models:
            yield event.plain_result("暂无可用的对话模型。")
            return
        names = "\n".join(f"- {m['id']}（{m.get('name', '')}）" for m in models[:40])
        yield event.plain_result(f"共 {len(models)} 个模型：\n{names}")

    @filter.command("cbkey")
    async def cbkey(self, event: AstrMessageEvent):
        """查看本地网关 Key（配置 OpenAI Compatible 时用）：/cbkey"""
        yield event.plain_result(
            f"Base URL：http://127.0.0.1:{self.port}/v1\n" + f"Key：{self.local_key}"
        )

    @filter.command("cblogout")
    async def cblogout(self, event: AstrMessageEvent):
        """注销 CodeBuddy：/cblogout"""
        self.client.logout()
        yield event.plain_result("已注销 CodeBuddy。下次使用前需要重新 /cblogin。")

    # ── 模型列表（TTL 缓存） ─────────────────────────────────────────────

    async def _get_models(self) -> list[dict]:
        if not self._models or (time.time() - self._models_ts) > MODEL_CACHE_TTL:
            self._models = await self.client.list_models()
            self._models_ts = time.time()
        return self._models

    # ── 本地 OpenAI 兼容网关 ─────────────────────────────────────────────

    async def _start_gateway(self):
        app = web.Application()
        app.router.add_get("/v1/models", self._handle_models)
        app.router.add_post("/v1/chat/completions", self._handle_chat)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", self.port)
        await site.start()
        self._gateway_runner = runner
        logger.info(
            f"[CodeBuddy] OpenAI 兼容网关已监听 http://127.0.0.1:{self.port}/v1 "
            f"（Key: {self.local_key}）"
        )

    def _check_auth(self, request: web.Request) -> bool:
        auth = request.headers.get("Authorization", "")
        return auth == f"Bearer {self.local_key}"

    async def _handle_models(self, request: web.Request):
        if not self._check_auth(request):
            return web.json_response(
                {"error": {"message": "invalid api key", "type": "invalid_request_error"}}, status=401
            )
        try:
            models = await self._get_models()
        except Exception as e:  # noqa: BLE001
            return web.json_response(
                {"error": {"message": f"codebuddy model fetch failed: {e}", "type": "api_error"}},
                status=502,
            )
        return web.json_response({
            "object": "list",
            "data": [
                {"id": m["id"], "object": "model", "created": 0, "owned_by": "codebuddy"}
                for m in models
            ],
        })

    async def _handle_chat(self, request: web.Request):
        if not self._check_auth(request):
            return web.json_response(
                {"error": {"message": "invalid api key", "type": "invalid_request_error"}}, status=401
            )
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            return web.json_response(
                {"error": {"message": "invalid json body", "type": "invalid_request_error"}}, status=400
            )
        model = body.get("model") or self.default_model
        messages = body.get("messages") or []
        stream = bool(body.get("stream", False))
        max_tokens = body.get("max_tokens")
        temperature = body.get("temperature")
        if not model or not messages:
            return web.json_response(
                {"error": {"message": "model and messages are required", "type": "invalid_request_error"}},
                status=400,
            )
        if stream:
            return await self._handle_chat_stream(request, messages, model, max_tokens, temperature)
        try:
            answer = await self.client.chat(messages, model, max_tokens=max_tokens, temperature=temperature)
        except CodeBuddyError as e:
            return web.json_response(
                {"error": {"message": str(e), "type": "api_error"}}, status=502
            )
        return web.json_response({
            "id": f"chatcmpl-{secrets.token_hex(8)}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": answer},
                "finish_reason": "stop",
            }],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        })

    async def _handle_chat_stream(
        self,
        request: web.Request,
        messages: list[dict],
        model: str,
        max_tokens: Optional[int],
        temperature: Optional[float],
    ):
        resp = web.StreamResponse(status=200)
        resp.headers["Content-Type"] = "text/event-stream; charset=utf-8"
        resp.headers["Cache-Control"] = "no-cache"
        resp.headers["X-Accel-Buffering"] = "no"
        await resp.prepare(request)
        cid = f"chatcmpl-{secrets.token_hex(8)}"

        def frame(delta: dict, finish: Optional[str]):
            return {
                "id": cid,
                "object": "chat.completion.chunk",
                "created": int(time.time()),
                "model": model,
                "choices": [{"index": 0, "delta": delta, "finish_reason": finish}],
            }

        try:
            first = True
            async for event in self.client.stream_chat(
                messages, model, max_tokens=max_tokens, temperature=temperature
            ):
                if event.kind == "content":
                    if first:
                        await resp.write(
                            f"data: {json.dumps(frame({'role': 'assistant'}, None), ensure_ascii=False)}\n\n"
                            .encode("utf-8")
                        )
                        first = False
                    await resp.write(
                        f"data: {json.dumps(frame({'content': event.text}, None), ensure_ascii=False)}\n\n"
                        .encode("utf-8")
                    )
                elif event.kind == "error":
                    await resp.write(
                        f'data: {json.dumps({"error": {"message": event.text, "type": "api_error"}}, ensure_ascii=False)}\n\n'
                        .encode("utf-8")
                    )
                    break
            await resp.write(f"data: {json.dumps(frame({}, 'stop'), ensure_ascii=False)}\n\n".encode("utf-8"))
            await resp.write(b"data: [DONE]\n\n")
        except Exception as e:  # noqa: BLE001
            logger.error(f"[CodeBuddy] 流式对话异常: {e}")
        await resp.write_eof()
        return resp

    # ── 生命周期 ─────────────────────────────────────────────────────────

    async def terminate(self):
        """插件卸载/停用时释放资源。"""
        if self._gateway_runner is not None:
            try:
                await self._gateway_runner.cleanup()
            except Exception:  # noqa: BLE001
                pass
        try:
            await self.client.aclose()
        except Exception:  # noqa: BLE001
            pass