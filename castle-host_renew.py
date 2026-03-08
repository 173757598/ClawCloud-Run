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

try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

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


@dataclass
class Config:
    cookies_list: List[str]
    tg_token: Optional[str]
    tg_chat_id: Optional[str]
    repo_token: Optional[str]
    repository: Optional[str]
    headless: bool
    debug_network: bool

    @classmethod
    def from_env(cls) -> "Config":
        raw = os.environ.get("CASTLE_COOKIES", "").strip()
        cookies_list = [c.strip() for c in raw.split(",") if c.strip()] if raw else []

        if not cookies_list:
            cookies_file = os.environ.get("CASTLE_COOKIES_FILE", "").strip()
            if cookies_file:
                cookies_list = load_cookies_from_file(cookies_file)

        return cls(
            cookies_list=cookies_list,
            tg_token=os.environ.get("TG_BOT_TOKEN"),
            tg_chat_id=os.environ.get("TG_CHAT_ID"),
            repo_token=os.environ.get("REPO_TOKEN"),
            repository=os.environ.get("GITHUB_REPOSITORY"),
            headless=parse_bool_env("HEADLESS", True),
            debug_network=parse_bool_env("DEBUG_NETWORK", True)
        )


def ensure_output_dir():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def sanitize_filename_part(value: str) -> str:
    return re.sub(r'[\\/:*?"<>|]', "_", value)


def screenshot_path(account_idx: int, server_id: str, stage: str) -> str:
    timestamp = datetime.now().strftime("%H%M%S")
    masked = sanitize_filename_part(mask_id(server_id))
    filename = f"acc{account_idx + 1}_{masked}_{stage}_{timestamp}.png"
    return str(OUTPUT_DIR / filename)


def mask_id(sid: str) -> str:
    return f"{sid[0]}***{sid[-2:]}" if len(sid) > 3 else "***"


def convert_date(s: str) -> str:
    m = re.match(r"(\d{2})\.(\d{2})\.(\d{4})", s) if s else None
    return f"{m.group(3)}-{m.group(2)}-{m.group(1)}" if m else "Unknown"


def days_left(s: str) -> int:
    try:
        return (datetime.strptime(s, "%d.%m.%Y") - datetime.now()).days
    except:
        return 0


def parse_bool_env(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def load_cookies_from_file(file_path: str) -> List[str]:
    try:
        p = Path(file_path)
        if not p.exists():
            logger.warning(f"⚠️ Cookie文件不存在: {file_path}")
            return []

        lines = p.read_text(encoding="utf-8").splitlines()
        return [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]
    except Exception as e:
        logger.error(f"❌ 读取Cookie文件失败: {e}")
        return []


def parse_cookies(s: str) -> List[Dict]:
    cookies = []
    for p in s.split(";"):
        p = p.strip()
        if "=" in p:
            n, v = p.split("=", 1)
            cookies.append({"name": n.strip(), "value": v.strip(), "domain": ".castle-host.com", "path": "/"})
    return cookies


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

    def __init__(self, ctx: BrowserContext, page: Page, account_idx: int, debug_network: bool = False):
        self.ctx, self.page = ctx, page
        self.account_idx = account_idx
        self.debug_network = debug_network

    @staticmethod
    def _safe_snippet(text: Optional[str], limit: int = 300) -> str:
        if not text:
            return ""
        t = text.replace("\n", "\\n")
        return t[:limit] + ("..." if len(t) > limit else "")

    async def _read_api_response(self, response, action_name: str) -> Dict:
        req = response.request
        post_data = req.post_data or ""
        body_text = ""

        try:
            body_text = await response.text()
        except Exception:
            body_text = ""

        if self.debug_network:
            logger.info(f"🧪 [{action_name}] Request: {req.method} {req.url}")
            if post_data:
                logger.info(f"🧪 [{action_name}] PostData: {self._safe_snippet(post_data, 500)}")
            logger.info(f"🧪 [{action_name}] Response: status={response.status}, body={self._safe_snippet(body_text, 800)}")

        if body_text:
            try:
                parsed = json.loads(body_text)
                if isinstance(parsed, dict):
                    return parsed
                return {"_raw_text": body_text, "_parsed": parsed}
            except Exception:
                return {"_raw_text": body_text}

        try:
            parsed = await response.json()
            if isinstance(parsed, dict):
                return parsed
            return {"_parsed": parsed}
        except Exception:
            return {}

    async def _goto_with_fallback(self, url: str):
        try:
            await self.page.goto(url, wait_until="domcontentloaded", timeout=45000)
        except Exception as e:
            logger.warning(f"⚠️ 页面加载超时，尝试load回退: {url} ({e})")
            await self.page.goto(url, wait_until="load", timeout=45000)
        await self.page.wait_for_timeout(2000)

    async def _goto_servers_page(self):
        await self._goto_with_fallback(f"{self.BASE}/servers")

    async def take_screenshot(self, server_id: str, stage: str) -> str:
        try:
            path = screenshot_path(self.account_idx, server_id, stage)
            await self.page.screenshot(path=path, full_page=True)
            logger.info("📸 截图已保存")
            return path
        except Exception as e:
            logger.error(f"❌ 截图失败: {e}")
            return ""

    async def get_server_ids(self) -> List[str]:
        """从服务器列表页获取服务器ID"""
        try:
            await self._goto_servers_page()
            match = re.search(r'var\s+ServersID\s*=\s*\[([\d,\s]+)\]', await self.page.content())
            if match:
                ids = [x.strip() for x in match.group(1).split(",") if x.strip()]
                logger.info(f"📋 找到 {len(ids)} 个服务器: {[mask_id(x) for x in ids]}")
                return ids
        except Exception as e:
            logger.error(f"❌ 获取服务器ID失败: {e}")
        return []

    async def check_server_stopped(self, sid: str) -> bool:
        """检查服务器是否关机（在 /servers 页面）"""
        try:
            start_btn = self.page.locator(f'button.icon-server-bstop[onclick*="sendAction({sid},\'start\')"]')
            if await start_btn.count() > 0:
                return True
            return False
        except:
            return False

    async def start_server_via_api(self, sid: str) -> bool:
        """优先点击按钮启动服务器，必要时回退到JS调用"""
        masked = mask_id(sid)
        start_url_match = lambda r: "/servers/control/action/" in r.url and "/start" in r.url

        try:
            if "/servers" not in self.page.url or "/control" in self.page.url or "/pay" in self.page.url:
                await self._goto_servers_page()

            if not await self.check_server_stopped(sid):
                logger.info(f"✅ 服务器 {masked} 已在运行")
                return False

            logger.info(f"🔴 服务器 {masked} 已关机，正在启动...")

            response_data: Dict = {}
            start_btn = self.page.locator(f"button.icon-server-bstop[onclick*=\"sendAction({sid},'start')\"]")

            if await start_btn.count() > 0:
                try:
                    logger.info("🔄 点击启动按钮...")
                    async with self.page.expect_response(start_url_match, timeout=12000) as resp_info:
                        await start_btn.first.click()
                    response_data = await self._read_api_response(await resp_info.value, "START")
                except Exception as e:
                    logger.warning(f"⚠️ 点击启动按钮未捕获到响应: {e}")

            if not response_data:
                try:
                    logger.info("🔄 回退到 sendAction 启动...")
                    async with self.page.expect_response(start_url_match, timeout=12000) as resp_info:
                        await self.page.evaluate(f"sendAction({sid}, 'start')")
                    response_data = await self._read_api_response(await resp_info.value, "START")
                except Exception as e:
                    logger.warning(f"⚠️ sendAction 未捕获到响应: {e}")

            if response_data:
                logger.info(f"📡 启动API响应: {response_data}")

            result = response_data
            if result.get("status") == "success":
                logger.info(f"🟢 服务器 {masked} 启动成功")
                await self.page.wait_for_timeout(3000)
                await self._goto_servers_page()
                return True

            if result.get("status") == "error":
                logger.warning(f"⚠️ 启动失败: {result.get('error', '未知错误')}")
                return False

            text = str(result.get("_raw_text", ""))
            if "success" in text.lower():
                logger.info(f"🟢 服务器 {masked} 启动指令已发送")
                await self.page.wait_for_timeout(3000)
                await self._goto_servers_page()
                return True

            logger.warning("⚠️ 启动响应未知")
            return False

        except Exception as e:
            logger.error(f"❌ 启动服务器 {masked} 失败: {e}")
        return False

    async def renew(self, sid: str) -> Tuple[RenewalStatus, str, str, str, int]:
        """续约服务器"""
        masked = mask_id(sid)
        screenshot_file = ""
        expiry = ""
        days = 0

        async def open_pay_page():
            await self._goto_with_fallback(f"{self.BASE}/servers/pay/index/{sid}")

        async def click_and_capture(action_name: str) -> Dict:
            renew_url_match = lambda r: "/servers/pay/buy_months/" in r.url
            renew_btn_local = self.page.locator("#freebtn")
            if await renew_btn_local.count() == 0:
                return {}

            try:
                async with self.page.expect_response(renew_url_match, timeout=12000) as resp_info:
                    logger.info(f"🖱️ 服务器 {masked} 已请求续约")
                    await renew_btn_local.first.click()
                return await self._read_api_response(await resp_info.value, action_name)
            except Exception as e:
                logger.warning(f"⚠️ 未捕获到续约API响应: {e}")
                await self.page.wait_for_timeout(1500)
                return {}

        try:
            logger.info(f"📄 访问续约页面...")
            await open_pay_page()

            content = await self.page.text_content("body")
            match = re.search(r"(\d{2}\.\d{2}\.\d{4})", content or "")
            if match:
                expiry = match.group(1)
                days = days_left(expiry)
                logger.info(f"📅 到期: {convert_date(expiry)} ({days}天)")

            renew_btn = self.page.locator('#freebtn')
            if await renew_btn.count() == 0:
                logger.error(f"❌ 找不到续约按钮")
                screenshot_file = await self.take_screenshot(sid, "no_button")
                return RenewalStatus.FAILED, "找不到续约按钮", screenshot_file, expiry, days

            data = await click_and_capture("RENEW")
            if data:
                logger.info(f"📡 续约API响应: {data}")

            if data.get("status") == "error":
                error_msg = data.get("error", "未知错误")
                m = error_msg.lower()
                if "валидации" in m or "csrf" in m:
                    logger.warning("⚠️ 检测到CSRF/校验失败，重试一次...")
                    await open_pay_page()
                    retry_btn = self.page.locator('#freebtn')
                    if await retry_btn.count() > 0:
                        retry_data = await click_and_capture("RENEW-RETRY")
                        if retry_data:
                            logger.info(f"📡 续约API重试响应: {retry_data}")
                            data = retry_data

            if data.get("status") == "success":
                logger.info(f"📝 结果: ✅ 续约成功")
                await self.page.wait_for_timeout(1000)
                screenshot_file = await self.take_screenshot(sid, "success")
                return RenewalStatus.SUCCESS, "续约成功", screenshot_file, expiry, days

            success_toast = self.page.locator('.iziToast-message:has-text("Успешно")')
            if await success_toast.count() > 0:
                logger.info(f"📝 结果: ✅ 续约成功")
                screenshot_file = await self.take_screenshot(sid, "success")
                return RenewalStatus.SUCCESS, "续约成功", screenshot_file, expiry, days

            if data.get("status") == "error":
                error_msg = data.get("error", "未知错误")
                m = error_msg.lower()

                if "24 час" in m or "уже продлен" in m:
                    logger.info(f"📝 结果: 今日已续期(24小时限制)")
                    screenshot_file = await self.take_screenshot(sid, "limited")
                    return RenewalStatus.RATE_LIMITED, "今日已续期(24小时限制)", screenshot_file, expiry, days

                if "недостаточно" in m:
                    logger.info(f"📝 结果: 余额不足")
                    screenshot_file = await self.take_screenshot(sid, "failed")
                    return RenewalStatus.FAILED, "余额不足", screenshot_file, expiry, days

                if "валидации" in m or "csrf" in m:
                    logger.info(f"📝 结果: CSRF验证失败")
                    screenshot_file = await self.take_screenshot(sid, "csrf_failed")
                    return RenewalStatus.FAILED, "CSRF验证失败", screenshot_file, expiry, days

                logger.info(f"📝 结果: {error_msg}")
                screenshot_file = await self.take_screenshot(sid, "failed")
                return RenewalStatus.FAILED, error_msg, screenshot_file, expiry, days

            raw = str(data.get("_raw_text", "")) if isinstance(data, dict) else ""
            logger.info(f"📝 结果: 未知响应")
            screenshot_file = await self.take_screenshot(sid, "unknown")
            return RenewalStatus.FAILED, raw if raw else (str(data) if data else "无响应"), screenshot_file, expiry, days

        except Exception as e:
            logger.error(f"❌ 续约服务器 {masked} 异常: {e}")
            screenshot_file = await self.take_screenshot(sid, "exception")
            return RenewalStatus.FAILED, str(e), screenshot_file, expiry, days

    async def extract_cookies(self) -> Optional[str]:
        try:
            cc = [c for c in await self.ctx.cookies() if "castle-host.com" in c.get("domain", "")]
            return "; ".join([f"{c['name']}={c['value']}" for c in cc]) if cc else None
        except:
            return None


async def process_account(
    cookie_str: str,
    idx: int,
    notifier: Notifier,
    headless: bool = True,
    debug_network: bool = False
) -> Tuple[Optional[str], List[ServerResult]]:
    cookies = parse_cookies(cookie_str)
    if not cookies:
        logger.error(f"❌ 账号#{idx + 1} Cookie解析失败")
        return None, []

    logger.info(f"{'=' * 50}")
    logger.info(f"📌 处理账号 #{idx + 1}")

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=headless, args=["--no-sandbox"])
        ctx = await browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            viewport={"width": 1920, "height": 1080}
        )
        await ctx.add_cookies(cookies)
        page = await ctx.new_page()
        page.set_default_timeout(PAGE_TIMEOUT)
        client = CastleClient(ctx, page, idx, debug_network=debug_network)
        results: List[ServerResult] = []

        try:
            server_ids = await client.get_server_ids()
            if not server_ids:
                if "login" in page.url:
                    logger.error(f"❌ 账号#{idx + 1} Cookie已失效")
                    error_screenshot = await client.take_screenshot("login", "expired")
                    await notifier.send_photo(
                        f"❌ Castle-Host 账号#{idx + 1}\n\nCookie已失效，请更新\n\n"
                        f"⏰ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                        error_screenshot
                    )
                return None, []

            for sid in server_ids:
                masked = mask_id(sid)
                logger.info(f"--- 处理服务器 {masked} ---")

                started = await client.start_server_via_api(sid)

                status, msg, screenshot, expiry, days = await client.renew(sid)

                results.append(ServerResult(sid, status, msg, expiry, days, started, screenshot))

                if len(server_ids) > 1 and sid != server_ids[-1]:
                    await client._goto_servers_page()

            for r in results:
                if r.status == RenewalStatus.SUCCESS:
                    status_icon, status_text = "✅", "续约成功"
                elif r.status == RenewalStatus.RATE_LIMITED:
                    status_icon, status_text = "⏭️", "今日已续期"
                else:
                    status_icon, status_text = "❌", f"续约失败: {r.message}"

                started_line = "🟢 服务器已启动\n" if r.started else ""
                masked_id = mask_id(r.server_id)
                caption = (
                    f"🖥️ Castle-Host 自动续约\n\n"
                    f"状态: {status_icon} {status_text}\n"
                    f"账号: #{idx + 1}\n\n"
                    f"💻 服务器: {masked_id}\n"
                    f"📅 到期: {convert_date(r.expiry)}\n"
                    f"⏳ 剩余: {r.days} 天\n"
                    f"{started_line}\n"
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
                f"❌ Castle-Host 账号#{idx + 1}\n\n异常: {e}\n\n"
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
        logger.error("❌ 未设置 CASTLE_COOKIES，且 CASTLE_COOKIES_FILE 无有效内容")
        return

    logger.info(f"📊 共 {len(config.cookies_list)} 个账号")
    logger.info(f"🧭 运行模式: HEADLESS={config.headless}, DEBUG_NETWORK={config.debug_network}")

    notifier = Notifier(config.tg_token, config.tg_chat_id)
    github = GitHubManager(config.repo_token, config.repository)

    new_cookies, changed = [], False

    for i, cookie in enumerate(config.cookies_list):
        new, _ = await process_account(
            cookie,
            i,
            notifier,
            headless=config.headless,
            debug_network=config.debug_network
        )
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
