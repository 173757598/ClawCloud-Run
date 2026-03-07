#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Castle-Host 服务器自动续约脚本 (带截图)
功能：多账号支持 + 自动启动关机服务器 + Cookie自动更新 + 截图通知
配置变量:CASTLE_COOKIES=PHPSESSID=xxx; uid=xxx,PHPSESSID=xxx; uid=xxx  (多账号用,逗号分隔)
"""

import os
import sys
import re
import json
import logging
import asyncio
import aiohttp
from pathlib import Path
from enum import Enum
from base64 import b64encode
from datetime import datetime
from dataclasses import dataclass
from typing import Optional, Tuple, List, Dict
from playwright.async_api import async_playwright, BrowserContext, Page

LOG_FILE = "castle_renew.log"
REQUEST_TIMEOUT = 30
PAGE_TIMEOUT = 60000
OUTPUT_DIR = Path("output/screenshots")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout), logging.FileHandler(LOG_FILE, encoding="utf-8")]
)
logger = logging.getLogger(__name__)


class RenewalStatus(Enum):
    SUCCESS = "success"
    FAILED = "failed"
    RATE_LIMITED = "rate_limited"


@dataclass
class ServerResult:
    server_id: str
    status: RenewalStatus
    message: str
    expiry: str = ""
    days: int = 0
    started: bool = False
    screenshot: str = ""
    debug_context: str = ""


@dataclass
class Config:
    cookies_list: List[str]
    tg_token: Optional[str]
    tg_chat_id: Optional[str]
    repo_token: Optional[str]
    repository: Optional[str]

    @classmethod
    def from_env(cls) -> "Config":
        raw = os.environ.get("CASTLE_COOKIES", "").strip()
        return cls(
            cookies_list=[c.strip() for c in raw.split(",") if c.strip()],
            tg_token=os.environ.get("TG_BOT_TOKEN"),
            tg_chat_id=os.environ.get("TG_CHAT_ID"),
            repo_token=os.environ.get("REPO_TOKEN"),
            repository=os.environ.get("GITHUB_REPOSITORY")
        )


def ensure_output_dir():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def screenshot_path(account_idx: int, server_id: str, stage: str) -> str:
    timestamp = datetime.now().strftime("%H%M%S")
    filename = f"acc{account_idx + 1}_{server_id}_{stage}_{timestamp}.png"
    return str(OUTPUT_DIR / filename)


def mask_id(sid: str) -> str:
    return f"{sid[0]}***{sid[-2:]}" if len(sid) > 3 else sid


def convert_date(s: str) -> str:
    m = re.match(r"(\d{2})\.(\d{2})\.(\d{4})", s) if s else None
    return f"{m.group(3)}-{m.group(2)}-{m.group(1)}" if m else "Unknown"


def days_left(s: str) -> int:
    try:
        return (datetime.strptime(s, "%d.%m.%Y") - datetime.now()).days
    except:
        return 0


def parse_cookies(s: str) -> List[Dict]:
    cookies = []
    for p in s.split(";"):
        p = p.strip()
        if "=" in p:
            n, v = p.split("=", 1)
            cookies.append({"name": n.strip(), "value": v.strip(), "domain": ".castle-host.com", "path": "/"})
    return cookies




def analyze_error(msg: str) -> Tuple[RenewalStatus, str]:
    m = msg.lower()
    if "24 час" in m or "уже продлен" in m or "24 hour" in m:
        return RenewalStatus.RATE_LIMITED, "今日已续期(24小时限制)"
    if "недостаточно" in m or "insufficient" in m:
        return RenewalStatus.FAILED, "余额不足"
    if "vksub" in m:
        return RenewalStatus.FAILED, "需要加入VK群组"
    if "csrf" in m or "token mismatch" in m:
        return RenewalStatus.FAILED, "CSRF验证失败"
    if "валидации" in m or "validation" in m:
        return RenewalStatus.FAILED, "请求参数验证失败"
    return RenewalStatus.FAILED, msg


def _sanitize_debug_value(key: str, value: str) -> str:
    key_lower = key.lower()
    if any(secret in key_lower for secret in ["token", "cookie", "session", "csrf"]):
        return "<redacted>"

    text = str(value).strip()
    if not text:
        return "<empty>"
    if len(text) > 40:
        return text[:37] + "..."
    return text


def sanitize_field_entries(entries: List[str]) -> List[str]:
    sanitized = []
    for entry in entries:
        if "=" in entry:
            key, value = entry.split("=", 1)
            sanitized.append(f"{key}={_sanitize_debug_value(key, value)}")
        else:
            sanitized.append(entry)
    return sanitized


def build_debug_context(dom_info: Dict, result: Optional[Dict] = None) -> str:
    body_keys = dom_info.get("body_keys", []) if isinstance(dom_info, dict) else []
    field_values = sanitize_field_entries(dom_info.get("field_values", [])) if isinstance(dom_info, dict) else []
    days_options = dom_info.get("days_options", []) if isinstance(dom_info, dict) else []
    candidate_text = ""
    candidate_attrs = ""
    if isinstance(dom_info, dict):
        candidate_text = str(dom_info.get("candidate_text", "")).strip()
        candidate_attrs = str(dom_info.get("candidate_attrs", "")).strip()
    if len(candidate_text) > 80:
        candidate_text = candidate_text[:77] + "..."
    if len(candidate_attrs) > 120:
        candidate_attrs = candidate_attrs[:117] + "..."

    parts = [
        f"表单={bool(dom_info.get('has_form'))}" if isinstance(dom_info, dict) else "表单=False",
        f"控件={bool(dom_info.get('has_click_target'))}" if isinstance(dom_info, dict) else "控件=False",
        f"字段={','.join(body_keys) if body_keys else 'none'}",
    ]

    if field_values:
        parts.append(f"值={';'.join(field_values)}")
    if days_options:
        parts.append(f"days选项={','.join(days_options)}")
    if candidate_text:
        parts.append(f"候选={candidate_text}")
    if candidate_attrs:
        parts.append(f"候选属性={candidate_attrs}")

    if isinstance(result, dict):
        request_url = str(result.get("request_url") or "")
        if request_url:
            parts.append(f"请求={request_url}")
        content_type = str(result.get("content_type") or "")
        if content_type:
            parts.append(f"类型={content_type}")

    return " | ".join(parts)


class Notifier:
    def __init__(self, token: Optional[str], chat_id: Optional[str]):
        self.token, self.chat_id = token, chat_id

    async def send_photo(self, caption: str, photo_path: str) -> Optional[int]:
        if not self.token or not self.chat_id:
            return None
        
        if not photo_path or not Path(photo_path).exists():
            return await self.send(caption)
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://api.telegram.org/bot{self.token}/sendPhoto"
                with open(photo_path, 'rb') as photo_file:
                    data = aiohttp.FormData()
                    data.add_field('chat_id', self.chat_id)
                    data.add_field('caption', caption)
                    data.add_field('photo', photo_file, filename='screenshot.png', content_type='image/png')
                    async with session.post(url, data=data, timeout=aiohttp.ClientTimeout(total=60)) as r:
                        if r.status == 200:
                            logger.info("✅ 通知已发送（带截图）")
                            return (await r.json()).get('result', {}).get('message_id')
                        else:
                            return await self.send(caption)
        except Exception as e:
            logger.error(f"❌ 通知异常: {e}")
            return await self.send(caption)

    async def send(self, msg: str) -> Optional[int]:
        if not self.token or not self.chat_id:
            return None
        try:
            async with aiohttp.ClientSession() as s:
                async with s.post(
                    f"https://api.telegram.org/bot{self.token}/sendMessage",
                    json={"chat_id": self.chat_id, "text": msg, "disable_web_page_preview": True},
                    timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)
                ) as r:
                    if r.status == 200:
                        logger.info("✅ 通知已发送")
                        return (await r.json()).get('result', {}).get('message_id')
        except Exception as e:
            logger.error(f"❌ 通知异常: {e}")
        return None


class GitHubManager:
    def __init__(self, token: Optional[str], repo: Optional[str]):
        self.token, self.repo = token, repo
        self.headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"} if token else {}

    async def update_secret(self, name: str, value: str) -> bool:
        if not self.token or not self.repo:
            return False
        try:
            from nacl import encoding, public
            async with aiohttp.ClientSession() as s:
                async with s.get(
                    f"https://api.github.com/repos/{self.repo}/actions/secrets/public-key",
                    headers=self.headers
                ) as r:
                    if r.status != 200:
                        return False
                    kd = await r.json()
                pk = public.PublicKey(kd["key"].encode(), encoding.Base64Encoder())
                enc = b64encode(public.SealedBox(pk).encrypt(value.encode())).decode()
                async with s.put(
                    f"https://api.github.com/repos/{self.repo}/actions/secrets/{name}",
                    headers=self.headers,
                    json={"encrypted_value": enc, "key_id": kd["key_id"]}
                ) as r:
                    if r.status in [201, 204]:
                        logger.info(f"✅ Secret {name} 已更新")
                        return True
        except Exception as e:
            logger.error(f"❌ GitHub异常: {e}")
        return False


class CastleClient:
    BASE = "https://cp.castle-host.com"

    def __init__(self, ctx: BrowserContext, page: Page, account_idx: int):
        self.ctx, self.page = ctx, page
        self.account_idx = account_idx

    async def take_screenshot(self, server_id: str, stage: str) -> str:
        try:
            path = screenshot_path(self.account_idx, server_id, stage)
            await self.page.screenshot(path=path, full_page=True)
            logger.info(f"📸 截图已保存")
            return path
        except Exception as e:
            logger.error(f"❌ 截图失败: {e}")
            return ""

    async def get_server_ids(self) -> List[str]:
        try:
            await self.page.goto(f"{self.BASE}/servers", wait_until="networkidle")
            match = re.search(r'var\s+ServersID\s*=\s*\[([\d,\s]+)\]', await self.page.content())
            if match:
                ids = [x.strip() for x in match.group(1).split(",") if x.strip()]
                logger.info(f"📋 找到 {len(ids)} 个服务器: {[mask_id(x) for x in ids]}")
                return ids
        except Exception as e:
            logger.error(f"❌ 获取服务器ID失败: {e}")
        return []

    async def check_server_running(self) -> bool:
        """检查服务器是否运行中"""
        try:
            # 方法1: 检查状态文本 "Сервер запущен"
            running_text = self.page.locator('.shard-value:has-text("Сервер запущен")')
            if await running_text.count() > 0:
                return True
            
            # 方法2: 检查绿色状态图标
            green_icon = self.page.locator('i.bi-hdd-stack.text-success')
            if await green_icon.count() > 0:
                return True
            
            # 方法3: 检查是否有启动按钮（有则说明未运行）
            start_btn = self.page.locator('a.btn-control:has-text("Запустить")')
            if await start_btn.count() > 0 and await start_btn.is_visible():
                return False
            
            return True  # 默认认为运行中
        except:
            return True

    async def start_if_stopped(self, sid: str) -> bool:
        """进入控制页，如果服务器关机则启动"""
        masked = mask_id(sid)
        try:
            await self.page.goto(f"{self.BASE}/servers/control/index/{sid}", wait_until="networkidle")
            await self.page.wait_for_timeout(2000)

            # 检查是否已运行
            if await self.check_server_running():
                logger.info(f"✅ 服务器 {masked} 运行中")
                return False

            # 服务器未运行，尝试启动
            logger.info(f"🔴 服务器 {masked} 已关机，正在启动...")
            
            # 使用页面内 JavaScript 发送启动请求
            result = await self.page.evaluate(f"""
                async () => {{
                    try {{
                        const token = document.querySelector('meta[name="csrf-token"]')?.content;
                        if (!token) return {{ success: false, error: 'No CSRF token' }};
                        
                        const response = await fetch('/servers/control/action/{sid}/start', {{
                            method: 'POST',
                            headers: {{
                                'X-CSRF-TOKEN': token,
                                'X-Requested-With': 'XMLHttpRequest',
                                'Accept': 'application/json'
                            }}
                        }});
                        const data = await response.json();
                        return {{ success: true, data: data }};
                    }} catch (e) {{
                        return {{ success: false, error: e.message }};
                    }}
                }}
            """)
            
            if result.get('success'):
                await self.page.wait_for_timeout(5000)
                logger.info(f"🟢 服务器 {masked} 启动指令已发送")
                return True
            else:
                logger.error(f"❌ 启动失败: {result.get('error')}")
                # 尝试点击按钮作为备选
                start_btn = self.page.locator('a.btn-control:has-text("Запустить")').first
                if await start_btn.count() > 0:
                    await start_btn.click()
                    await self.page.wait_for_timeout(5000)
                    logger.info(f"🟢 服务器 {masked} 启动指令已发送(点击)")
                    return True

        except Exception as e:
            logger.error(f"❌ 启动服务器 {masked} 失败: {e}")
        return False

    async def get_expiry(self, sid: str) -> str:
        """获取到期时间"""
        try:
            await self.page.goto(f"{self.BASE}/servers/pay/index/{sid}", wait_until="networkidle")
            await self.page.wait_for_timeout(1500)
            
            content = await self.page.text_content("body")
            match = re.search(r"(\d{2}\.\d{2}\.\d{4})", content)
            return match.group(1) if match else ""
        except Exception as e:
            logger.error(f"❌ 获取到期时间失败: {e}")
            return ""

    async def renew(self, sid: str) -> Tuple[RenewalStatus, str, str]:
        """续约服务器 - 优先触发页面真实续约控件，失败后回退到 fetch 提交"""
        masked = mask_id(sid)
        screenshot_file = ""
        debug_context = ""

        try:
            current_url = self.page.url
            if f"/pay/index/{sid}" not in current_url:
                await self.page.goto(f"{self.BASE}/servers/pay/index/{sid}", wait_until="networkidle")
                await self.page.wait_for_timeout(1500)

            dom_info = await self.page.evaluate(
                """
                (sid) => {
                    const endpointPath = `/servers/pay/buy_months/${sid}`;
                    const renewTextRegex = /(buy[_-]?months|продлить|renew|extend|месяц|month)/i;

                    const clearMarker = (name) => {
                        document.querySelectorAll(`[data-cc-${name}]`).forEach(el => el.removeAttribute(`data-cc-${name}`));
                    };

                    const mark = (el, name) => {
                        if (!el) return '';
                        clearMarker(name);
                        el.setAttribute(`data-cc-${name}`, sid);
                        return `[data-cc-${name}="${sid}"]`;
                    };

                    const attrText = (el) => [
                        el.getAttribute('action'),
                        el.getAttribute('href'),
                        el.getAttribute('data-url'),
                        el.getAttribute('data-action'),
                        el.getAttribute('formaction'),
                        el.getAttribute('onclick')
                    ].filter(Boolean).join(' ');

                    const textOf = (el) => ((el.textContent || el.value || '').replace(/\\s+/g, ' ').trim());

                    const isVisible = (el) => {
                        if (!el) return false;
                        const style = window.getComputedStyle(el);
                        const rect = el.getBoundingClientRect();
                        return style.display !== 'none' && style.visibility !== 'hidden' && rect.width > 0 && rect.height > 0;
                    };

                    const addField = (entries, key, value) => {
                        if (!key || value == null || value === '') return;
                        entries.push([String(key), String(value)]);
                    };

                    const normalizeUrl = (value) => {
                        if (!value) return '';
                        try {
                            return new URL(value, window.location.origin).toString();
                        } catch (_) {
                            return value;
                        }
                    };

                    const compactAttrText = (el) => {
                        if (!el) return '';
                        return [
                            ['name', el.getAttribute('name')],
                            ['value', el.getAttribute('value')],
                            ['href', el.getAttribute('href')],
                            ['data-url', el.getAttribute('data-url')],
                            ['data-action', el.getAttribute('data-action')],
                            ['onclick', el.getAttribute('onclick')],
                        ].filter(([, value]) => value).map(([key, value]) => `${key}=${String(value).replace(/\\s+/g, ' ').trim()}`).join('; ');
                    };

                    const collectDayOptions = () => {
                        const values = new Set();
                        document.querySelectorAll('select[name="days"] option').forEach(option => {
                            if (option.value) values.add(String(option.value));
                        });
                        document.querySelectorAll('input[name="days"]').forEach(input => {
                            if (input.value) values.add(String(input.value));
                        });
                        return Array.from(values);
                    };

                    const ensureDaysValue = (entries) => {
                        const hasDays = entries.some(([key, value]) => key === 'days' && String(value).trim());
                        if (hasDays) return;

                        const selectedOption = document.querySelector('select[name="days"] option:checked')?.value;
                        if (selectedOption) {
                            addField(entries, 'days', selectedOption);
                            return;
                        }

                        const firstOption = document.querySelector('select[name="days"] option[value]')?.value;
                        if (firstOption) {
                            const select = document.querySelector('select[name="days"]');
                            if (select) select.value = firstOption;
                            addField(entries, 'days', firstOption);
                            return;
                        }

                        const checkedRadio = document.querySelector('input[name="days"]:checked')?.value;
                        if (checkedRadio) {
                            addField(entries, 'days', checkedRadio);
                            return;
                        }

                        const firstRadio = document.querySelector('input[name="days"]')?.value;
                        if (firstRadio) {
                            const radio = document.querySelector('input[name="days"]');
                            if (radio) radio.checked = true;
                            addField(entries, 'days', firstRadio);
                        }
                    };

                    const summarizeEntries = (entries) => entries.map(([key, value]) => `${key}=${String(value).trim() || '<empty>'}`);

                    const forms = Array.from(document.querySelectorAll('form'));
                    const exactForm = forms.find(form => {
                        const action = form.getAttribute('action') || form.action || '';
                        return action.includes('/servers/pay/buy_months/') || action.includes(endpointPath);
                    }) || null;

                    const clickables = Array.from(document.querySelectorAll('a, button, input[type="submit"], input[type="button"], [role="button"], [onclick], [data-url], [data-action], [formaction]'));
                    const scoreClickable = (el) => {
                        const attrs = attrText(el);
                        const text = textOf(el);
                        let score = 0;
                        if (attrs.includes(endpointPath)) score += 8;
                        if (attrs.includes('/servers/pay/buy_months/')) score += 6;
                        if (renewTextRegex.test(attrs)) score += 3;
                        if (renewTextRegex.test(text)) score += 2;
                        if (isVisible(el)) score += 1;
                        if (el.closest('form') === exactForm && exactForm) score += 2;
                        return score;
                    };

                    const bestClickable = clickables
                        .map(el => ({ el, score: scoreClickable(el) }))
                        .filter(item => item.score > 0)
                        .sort((a, b) => b.score - a.score)[0]?.el || null;

                    const sourceForm = exactForm || bestClickable?.closest('form') || null;
                    const submitter = sourceForm
                        ? Array.from(sourceForm.querySelectorAll('button, input[type="submit"], input[type="button"], a, [role="button"], [onclick], [data-url], [data-action], [formaction]'))
                            .map(el => ({ el, score: scoreClickable(el) }))
                            .filter(item => item.score > 0)
                            .sort((a, b) => b.score - a.score)[0]?.el || null
                        : null;

                    const tokenFromMeta = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
                    const tokenFromInput = sourceForm?.querySelector('input[name="_token"]')?.value || document.querySelector('input[name="_token"]')?.value || '';
                    const token = tokenFromInput || tokenFromMeta;

                    const bodyEntries = [];
                    if (sourceForm) {
                        const formData = new FormData(sourceForm);
                        if (submitter?.name && !formData.has(submitter.name)) {
                            formData.append(submitter.name, submitter.value || '1');
                        }
                        for (const [key, value] of formData.entries()) {
                            addField(bodyEntries, key, value);
                        }
                    } else {
                        const fieldSelectors = [
                            'input[type="hidden"][name]',
                            'input[type="radio"][name]:checked',
                            'input[type="checkbox"][name]:checked',
                            'select[name]',
                            'textarea[name]'
                        ];
                        document.querySelectorAll(fieldSelectors.join(',')).forEach(field => {
                            addField(bodyEntries, field.name, field.value);
                        });
                    }

                    const chosen = submitter || bestClickable;
                    if (chosen?.dataset) {
                        Object.entries(chosen.dataset).forEach(([key, value]) => {
                            if (/month|period|plan|tariff|product|server|id/i.test(key)) {
                                addField(bodyEntries, key, value);
                            }
                        });
                    }

                    ensureDaysValue(bodyEntries);

                    if (token && !bodyEntries.some(([key]) => key === '_token')) {
                        addField(bodyEntries, '_token', token);
                    }
                    if (!bodyEntries.some(([key]) => key === 'server_id')) {
                        addField(bodyEntries, 'server_id', sid);
                    }

                    const requestUrl = normalizeUrl(
                        sourceForm?.getAttribute('action')
                        || sourceForm?.action
                        || chosen?.getAttribute('formaction')
                        || chosen?.getAttribute('data-url')
                        || chosen?.getAttribute('data-action')
                        || chosen?.getAttribute('href')
                        || endpointPath
                    );

                    return {
                        token,
                        request_url: requestUrl,
                        body_entries: bodyEntries,
                        body_keys: Array.from(new Set(bodyEntries.map(([key]) => key))),
                        field_values: summarizeEntries(bodyEntries),
                        days_options: collectDayOptions(),
                        candidate_attrs: compactAttrText(chosen),
                        has_form: !!exactForm,
                        has_click_target: !!bestClickable,
                        form_selector: sourceForm ? mark(sourceForm, 'renew-form') : '',
                        submit_selector: submitter ? mark(submitter, 'renew-submit') : '',
                        click_selector: bestClickable ? mark(bestClickable, 'renew-click') : '',
                        candidate_text: textOf(chosen || sourceForm || document.body).slice(0, 120)
                    };
                }
                """,
                sid,
            )

            safe_field_values = sanitize_field_entries(dom_info.get('field_values', []))
            logger.info(
                f"🔍 续约策略: 表单={dom_info.get('has_form')} | 控件={dom_info.get('has_click_target')} | 字段={','.join(dom_info.get('body_keys', [])) or 'none'} | 值={';'.join(safe_field_values) or 'none'} | days选项={','.join(dom_info.get('days_options', [])) or 'none'} | 候选={dom_info.get('candidate_text') or 'none'} | 候选属性={dom_info.get('candidate_attrs') or 'none'}"
            )

            result = None
            debug_context = build_debug_context(dom_info)

            try:
                click_selector = dom_info.get("click_selector")
                form_selector = dom_info.get("form_selector")
                submit_selector = dom_info.get("submit_selector")

                if click_selector or form_selector:
                    async with self.page.expect_response(
                        lambda response: f"/servers/pay/buy_months/{sid}" in response.url,
                        timeout=REQUEST_TIMEOUT * 1000,
                    ) as response_info:
                        if click_selector:
                            await self.page.locator(click_selector).first.click(force=True)
                        elif submit_selector:
                            await self.page.locator(submit_selector).first.click(force=True)
                        else:
                            await self.page.eval_on_selector(
                                form_selector,
                                "form => form.requestSubmit ? form.requestSubmit() : form.submit()",
                            )

                    response = await response_info.value
                    content_type = response.headers.get("content-type", "")
                    text = await response.text()
                    data = None

                    if text:
                        try:
                            data = json.loads(text)
                        except json.JSONDecodeError:
                            data = None

                    result = {
                        "success": True,
                        "status": response.status,
                        "ok": response.ok,
                        "url": response.url,
                        "request_url": response.url,
                        "has_form": dom_info.get("has_form"),
                        "content_type": content_type,
                        "data": data,
                        "text": text[:300] if text else "",
                    }
                    debug_context = build_debug_context(dom_info, result)
            except Exception as click_error:
                logger.warning(f"⚠️ 页面控件续约失败，回退到fetch: {click_error} | {debug_context}")

            if result is None:
                result = await self.page.evaluate(
                    """
                    async ({ sid, requestUrl, token, bodyEntries, hasForm }) => {
                        try {
                            const body = new URLSearchParams();
                            for (const [key, value] of bodyEntries || []) {
                                body.append(String(key), String(value));
                            }

                            const response = await fetch(requestUrl || `/servers/pay/buy_months/${sid}`, {
                                method: 'POST',
                                headers: {
                                    'X-CSRF-TOKEN': token || '',
                                    'X-Requested-With': 'XMLHttpRequest',
                                    'Accept': 'application/json, text/javascript, */*; q=0.01',
                                    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                                    'Referer': window.location.href
                                },
                                body,
                                credentials: 'same-origin'
                            });

                            const contentType = response.headers.get('content-type') || '';
                            let data = null;
                            let text = '';

                            if (contentType.includes('application/json')) {
                                data = await response.json();
                            } else {
                                text = await response.text();
                                try { data = JSON.parse(text); } catch (_) {}
                            }

                            return {
                                success: true,
                                status: response.status,
                                ok: response.ok,
                                url: response.url,
                                request_url: requestUrl || `/servers/pay/buy_months/${sid}`,
                                has_form: !!hasForm,
                                content_type: contentType,
                                data,
                                text: text ? text.slice(0, 300) : ''
                            };
                        } catch (e) {
                            return { success: false, error: e.message };
                        }
                    }
                    """,
                    {
                        "sid": sid,
                        "requestUrl": dom_info.get("request_url"),
                        "token": dom_info.get("token"),
                        "bodyEntries": dom_info.get("body_entries", []),
                        "hasForm": dom_info.get("has_form", False),
                    },
                )
                debug_context = build_debug_context(dom_info, result)

            logger.info(f"🖱️ 服务器 {masked} 已请求续约")
            if result.get('success'):
                logger.info(f"🔍 续约响应状态: {result.get('status')} | ok={result.get('ok')} | url={result.get('url')}")
                logger.info(f"🔍 续约请求URL: {result.get('request_url')} | 命中表单={result.get('has_form')}")
                if result.get('content_type'):
                    logger.info(f"🔍 续约响应类型: {result.get('content_type')}")

            if not result.get('success'):
                error_msg = result.get('error', '请求失败')
                logger.error(f"❌ 请求失败: {error_msg} | {debug_context}")
                screenshot_file = await self.take_screenshot(sid, "error")
                return RenewalStatus.FAILED, f"{error_msg} | {debug_context}", screenshot_file

            data = result.get('data', {})
            if not isinstance(data, dict):
                preview = result.get('text', '')
                logger.error(f"❌ 非JSON响应，HTTP {result.get('status')}，预览: {preview} | {debug_context}")
                screenshot_file = await self.take_screenshot(sid, "nonjson")
                return RenewalStatus.FAILED, f"HTTP {result.get('status')} 非JSON响应 | {debug_context}", screenshot_file

            await self.page.reload(wait_until="networkidle")
            await self.page.wait_for_timeout(1000)

            if data.get("status") == "error":
                error_msg = data.get("error", "未知错误")
                status, msg = analyze_error(error_msg)
                stage = "limited" if status == RenewalStatus.RATE_LIMITED else "failed"
                logger.info(f"📝 结果: {msg} | {debug_context}")
                screenshot_file = await self.take_screenshot(sid, stage)
                return status, f"{msg} | {debug_context}", screenshot_file

            if data.get("status") == "success":
                logger.info(f"📝 结果: ✅ 续约成功")
                screenshot_file = await self.take_screenshot(sid, "success")
                return RenewalStatus.SUCCESS, "续约成功", screenshot_file

            logger.info(f"📝 结果: 未知响应 {data} | {debug_context}")
            screenshot_file = await self.take_screenshot(sid, "unknown")
            return RenewalStatus.FAILED, f"{data} | {debug_context}", screenshot_file

        except Exception as e:
            logger.error(f"❌ 续约服务器 {masked} 异常: {e} | {debug_context}")
            screenshot_file = await self.take_screenshot(sid, "exception")
            return RenewalStatus.FAILED, f"{e} | {debug_context}", screenshot_file

    async def extract_cookies(self) -> Optional[str]:
        try:
            cc = [c for c in await self.ctx.cookies() if "castle-host.com" in c.get("domain", "")]
            return "; ".join([f"{c['name']}={c['value']}" for c in cc]) if cc else None
        except:
            return None


async def process_account(cookie_str: str, idx: int, notifier: Notifier) -> Tuple[Optional[str], List[ServerResult]]:
    cookies = parse_cookies(cookie_str)
    if not cookies:
        logger.error(f"❌ 账号#{idx + 1} Cookie解析失败")
        return None, []

    logger.info(f"{'=' * 50}")
    logger.info(f"📌 处理账号 #{idx + 1}")

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True, args=["--no-sandbox"])
        ctx = await browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            viewport={"width": 1920, "height": 1080}
        )
        await ctx.add_cookies(cookies)
        page = await ctx.new_page()
        page.set_default_timeout(PAGE_TIMEOUT)
        client = CastleClient(ctx, page, idx)
        results: List[ServerResult] = []

        try:
            server_ids = await client.get_server_ids()
            if not server_ids:
                if "login" in page.url:
                    logger.error(f"❌ 账号#{idx + 1} Cookie已失效")
                    error_screenshot = await client.take_screenshot("login", "expired")
                    await notifier.send_photo(
                        f"❌ Castle-Host 账号#{idx + 1}\n\n"
                        f"Cookie已失效，请更新\n\n"
                        f"📝 格式:\n"
                        f"CASTLE_COOKIES=PHPSESSID=xxx; uid=xxx,PHPSESSID=xxx; uid=xxx\n"
                        f"(多账号用,逗号分隔)\n\n"
                        f"⏰ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                        error_screenshot
                    )
                return None, []

            for sid in server_ids:
                masked = mask_id(sid)
                logger.info(f"--- 处理服务器 {masked} ---")
                
                # 启动服务器（如果关机）
                started = await client.start_if_stopped(sid)
                
                # 获取到期时间
                expiry = await client.get_expiry(sid)
                d = days_left(expiry)
                logger.info(f"📅 到期: {convert_date(expiry)} ({d}天)")
                
                # 续约
                status, msg, screenshot = await client.renew(sid)
                debug_context = ""
                if " | 表单=" in msg:
                    msg, debug_context = msg.split(" | 表单=", 1)
                    debug_context = f"表单={debug_context}"
                elif " | 控件=" in msg:
                    msg, debug_context = msg.split(" | 控件=", 1)
                    debug_context = f"控件={debug_context}"

                results.append(ServerResult(sid, status, msg, expiry, d, started, screenshot, debug_context))
                await asyncio.sleep(2)

            # 发送通知
            for r in results:
                if r.status == RenewalStatus.SUCCESS:
                    status_icon = "✅"
                    status_text = "续约成功"
                elif r.status == RenewalStatus.RATE_LIMITED:
                    status_icon = "⏭️"
                    status_text = "今日已续期"
                else:
                    status_icon = "❌"
                    status_text = f"续约失败: {r.message}"

                started_line = "🟢 服务器已启动\n" if r.started else ""
                
                debug_line = f"🔎 调试: {r.debug_context}\n" if r.debug_context else ""

                caption = (
                    f"🖥️ Castle-Host 自动续约\n\n"
                    f"状态: {status_icon} {status_text}\n"
                    f"账号: #{idx + 1}\n\n"
                    f"💻 服务器: {r.server_id}\n"
                    f"📅 到期: {convert_date(r.expiry)}\n"
                    f"⏳ 剩余: {r.days} 天\n"
                    f"{started_line}"
                    f"{debug_line}\n"
                    f"⏰ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                )
                
                await notifier.send_photo(caption, r.screenshot)

            new_cookie = await client.extract_cookies()
            if new_cookie and new_cookie != cookie_str:
                logger.info(f"🔄 账号#{idx + 1} Cookie已变化")
                return new_cookie, results
            return cookie_str, results

        except Exception as e:
            logger.error(f"❌ 账号#{idx + 1} 异常: {e}")
            error_screenshot = await client.take_screenshot("error", "exception")
            await notifier.send_photo(
                f"❌ Castle-Host 账号#{idx + 1}\n\n"
                f"异常: {e}\n\n"
                f"📝 Cookie格式:\n"
                f"CASTLE_COOKIES=PHPSESSID=xxx; uid=xxx,PHPSESSID=xxx; uid=xxx\n"
                f"(多账号用,逗号分隔)\n\n"
                f"⏰ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                error_screenshot
            )
            return None, []
        finally:
            await ctx.close()
            await browser.close()


async def main():
    logger.info("=" * 50)
    logger.info("🖥️ Castle-Host 自动续约")
    logger.info("=" * 50)

    ensure_output_dir()

    config = Config.from_env()
    if not config.cookies_list:
        logger.error("❌ 未设置 CASTLE_COOKIES")
        return

    logger.info(f"📊 共 {len(config.cookies_list)} 个账号")

    notifier = Notifier(config.tg_token, config.tg_chat_id)
    github = GitHubManager(config.repo_token, config.repository)

    new_cookies = []
    changed = False

    for i, cookie in enumerate(config.cookies_list):
        new, _ = await process_account(cookie, i, notifier)
        if new:
            new_cookies.append(new)
            if new != cookie:
                changed = True
        else:
            new_cookies.append(cookie)
        if i < len(config.cookies_list) - 1:
            await asyncio.sleep(5)

    if changed:
        await github.update_secret("CASTLE_COOKIES", ",".join(new_cookies))

    logger.info("👋 完成")


if __name__ == "__main__":
    asyncio.run(main())
