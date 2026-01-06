#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Castle-Host 服务器自动续约脚本
功能：自动续期 + Cookie自动更新 + GitHub Secrets同步

配置变量说明:
- 账号变量:
    - CASTLE_COOKIES=格式：PHPSESSID=ohxxxxxks5q; uid=R0RsTHxxxxx25b
    - SERVER_ID=服务器 ID 默认：118052
- GITHUB Token:
    - REPO_TOKEN=ghp_xxxxx 用于自动更新 Cookie
- 通知变量 (可选):
    - TG_BOT_TOKEN=Telegram 机器人 Token
    - TG_CHAT_ID=Telegram 聊天 ID
"""

import os
import sys
import re
import json
import logging
import asyncio
import aiohttp
from enum import Enum
from base64 import b64encode
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import Optional, Tuple, List, Dict
from playwright.async_api import async_playwright, BrowserContext, Page

# ==================== 配置 ====================

LOG_FILE = "castle_renew.log"
HISTORY_FILE = "renewal_history.json"
DEFAULT_SERVER_ID = "118052"
REQUEST_TIMEOUT = 10
PAGE_TIMEOUT = 60000

# ==================== 日志配置 ====================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_FILE, encoding="utf-8")
    ]
)
logger = logging.getLogger(__name__)

# ==================== 枚举定义 ====================

class RenewalStatus(Enum):
    SUCCESS = "success"
    FAILED = "failed"
    RATE_LIMITED = "rate_limited"
    OTHER = "other"

# ==================== 数据类 ====================

@dataclass
class ServerInfo:
    server_id: str
    expiry_date: Optional[str] = None
    expiry_formatted: Optional[str] = None
    days_left: Optional[int] = None
    balance: str = "0.00"
    url: str = ""

@dataclass
class RenewalResult:
    status: RenewalStatus
    message: str
    new_expiry: Optional[str] = None
    days_added: int = 0

@dataclass
class RenewalRecord:
    server_id: str
    renewal_time: str
    before_expiry: str
    after_expiry: str
    status: str
    message: str
    cookie_updated: bool = False

@dataclass
class Config:
    cookies: str
    server_id: str
    tg_token: Optional[str]
    tg_chat_id: Optional[str]
    repo_token: Optional[str]
    repository: Optional[str]

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            cookies=os.environ.get("CASTLE_COOKIES", "").strip(),
            server_id=os.environ.get("SERVER_ID", DEFAULT_SERVER_ID),
            tg_token=os.environ.get("TG_BOT_TOKEN"),
            tg_chat_id=os.environ.get("TG_CHAT_ID"),
            repo_token=os.environ.get("REPO_TOKEN"),
            repository=os.environ.get("GITHUB_REPOSITORY")
        )

# ==================== 工具函数 ====================

def mask_id(server_id: str) -> str:
    """隐藏ID用于日志: 117987 -> 1***54"""
    if len(server_id) <= 3:
        return server_id
    return f"{server_id[0]}***{server_id[-2:]}"

def convert_date_format(date_str: str) -> str:
    """DD.MM.YYYY -> YYYY-MM-DD"""
    if not date_str:
        return "Unknown"
    match = re.match(r"(\d{2})\.(\d{2})\.(\d{4})", date_str)
    if match:
        return f"{match.group(3)}-{match.group(2)}-{match.group(1)}"
    return date_str

def parse_date(date_str: str) -> Optional[datetime]:
    """解析日期字符串"""
    for fmt in ["%d.%m.%Y", "%Y-%m-%d"]:
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue
    return None

def calculate_days_left(date_str: str) -> Optional[int]:
    """计算剩余天数"""
    date_obj = parse_date(date_str)
    return (date_obj - datetime.now()).days if date_obj else None

def parse_cookies(cookie_str: str) -> List[Dict]:
    """解析Cookie字符串"""
    cookies = []
    for part in cookie_str.split(";"):
        part = part.strip()
        if "=" in part:
            name, value = part.split("=", 1)
            cookies.append({
                "name": name.strip(),
                "value": value.strip(),
                "domain": ".castle-host.com",
                "path": "/"
            })
    return cookies

def analyze_api_error(error_msg: str) -> Tuple[RenewalStatus, str]:
    """分析API错误信息"""
    error_lower = error_msg.lower()
    if "24 час" in error_lower or "уже продлен" in error_lower:
        return RenewalStatus.RATE_LIMITED, "今日已续期"
    if "недостаточно" in error_lower:
        return RenewalStatus.FAILED, "余额不足"
    if "максимальн" in error_lower:
        return RenewalStatus.FAILED, "已达最大期限"
    return RenewalStatus.FAILED, error_msg

# ==================== 通知模块 ====================

class Notifier:
    def __init__(self, tg_token: Optional[str], tg_chat_id: Optional[str]):
        self.tg_token = tg_token
        self.tg_chat_id = tg_chat_id
    
    def build_message(self, server: ServerInfo, result: RenewalResult) -> str:
        """构建通知消息"""
        status_line = self._get_status_line(result)
        expiry = convert_date_format(result.new_expiry) if result.new_expiry else server.expiry_formatted
        days = calculate_days_left(result.new_expiry) if result.new_expiry else server.days_left
        
        return f"""🎁 Castle-Host 自动续约通知

💻 服务器: {server.server_id}
📅 到期时间: {expiry or 'Unknown'}
⏳ 剩余天数: {days or 'Unknown'} 天
🔗 {server.url}

{status_line}"""
    
    def _get_status_line(self, result: RenewalResult) -> str:
        """获取状态行"""
        if result.status == RenewalStatus.SUCCESS:
            return f"✅ 续约成功 (+{result.days_added}天)" if result.days_added > 0 else "✅ 续约成功"
        elif result.status == RenewalStatus.FAILED:
            return f"❌ 续约失败: {result.message}"
        elif result.status == RenewalStatus.RATE_LIMITED:
            return "📝 今日已续期"
        return f"📝 {result.message}"
    
    async def send(self, message: str) -> bool:
        """发送Telegram通知"""
        if not self.tg_token or not self.tg_chat_id:
            logger.info("ℹ️ Telegram未配置")
            return False
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"https://api.telegram.org/bot{self.tg_token}/sendMessage",
                    json={"chat_id": self.tg_chat_id, "text": message, "parse_mode": "HTML"},
                    timeout=REQUEST_TIMEOUT
                ) as resp:
                    if resp.status == 200:
                        logger.info("✅ 通知已发送")
                        return True
                    logger.warning(f"⚠️ 通知发送失败: {resp.status}")
                    return False
        except Exception as e:
            logger.error(f"❌ 通知发送异常: {e}")
            return False

# ==================== GitHub模块 ====================

class GitHubSecretsManager:
    def __init__(self, repo_token: Optional[str], repository: Optional[str]):
        self.repo_token = repo_token
        self.repository = repository
        self.headers = {
            "Authorization": f"Bearer {repo_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        } if repo_token else {}
    
    async def update_secret(self, name: str, value: str) -> bool:
        """更新GitHub Secret"""
        if not self.repo_token or not self.repository:
            logger.info("ℹ️ GitHub未配置，跳过Secret更新")
            return False
        try:
            from nacl import encoding, public
        except ImportError:
            logger.error("❌ 缺少pynacl库")
            return False
        try:
            async with aiohttp.ClientSession() as session:
                key_url = f"https://api.github.com/repos/{self.repository}/actions/secrets/public-key"
                async with session.get(key_url, headers=self.headers) as resp:
                    if resp.status != 200:
                        logger.error(f"❌ 获取公钥失败: {resp.status}")
                        return False
                    key_data = await resp.json()
                
                public_key = public.PublicKey(key_data["key"].encode("utf-8"), encoding.Base64Encoder())
                sealed_box = public.SealedBox(public_key)
                encrypted = sealed_box.encrypt(value.encode("utf-8"))
                encrypted_value = b64encode(encrypted).decode("utf-8")
                
                secret_url = f"https://api.github.com/repos/{self.repository}/actions/secrets/{name}"
                async with session.put(
                    secret_url, headers=self.headers,
                    json={"encrypted_value": encrypted_value, "key_id": key_data["key_id"]}
                ) as resp:
                    if resp.status in [201, 204]:
                        logger.info(f"✅ Secret {name} 已更新")
                        return True
                    logger.error(f"❌ 更新Secret失败: {resp.status}")
                    return False
        except Exception as e:
            logger.error(f"❌ GitHub API异常: {e}")
            return False

# ==================== 浏览器模块 ====================

class CastleHostClient:
    def __init__(self, context: BrowserContext, page: Page, server_id: str):
        self.context = context
        self.page = page
        self.server_id = server_id
        self.url = f"https://cp.castle-host.com/servers/pay/index/{server_id}"
    
    async def get_server_info(self) -> ServerInfo:
        """获取服务器信息"""
        expiry = await self._extract_expiry()
        balance = await self._extract_balance()
        return ServerInfo(
            server_id=self.server_id,
            expiry_date=expiry,
            expiry_formatted=convert_date_format(expiry) if expiry else None,
            days_left=calculate_days_left(expiry) if expiry else None,
            balance=balance,
            url=self.url
        )
    
    async def _extract_expiry(self) -> Optional[str]:
        """提取到期时间"""
        try:
            text = await self.page.text_content("body")
            for pattern in [r"(\d{2}\.\d{2}\.\d{4})\s*\([^)]*\)", r"\b(\d{2}\.\d{2}\.\d{4})\b"]:
                match = re.search(pattern, text)
                if match:
                    return match.group(1)
        except Exception as e:
            logger.error(f"❌ 提取到期时间失败: {e}")
        return None
    
    async def _extract_balance(self) -> str:
        """提取余额"""
        try:
            text = await self.page.text_content("body")
            match = re.search(r"(\d+\.\d+)\s*₽", text)
            return match.group(1) if match else "0.00"
        except:
            return "0.00"
    
    async def renew(self) -> RenewalResult:
        """执行续约"""
        api_response: Dict = {}
        
        async def capture_response(response):
            if "/buy_months/" in response.url:
                try:
                    api_response["data"] = await response.json()
                except:
                    pass
        
        self.page.on("response", capture_response)
        
        for selector in ["#freebtn", 'button:has-text("Продлить")']:
            button = self.page.locator(selector)
            if await button.count() > 0:
                if await button.get_attribute("disabled"):
                    return RenewalResult(RenewalStatus.FAILED, "按钮已禁用")
                
                await button.click()
                logger.info("🖱️ 已点击续约按钮")
                
                for _ in range(20):
                    if api_response.get("data"):
                        break
                    await asyncio.sleep(0.5)
                
                if api_response.get("data"):
                    data = api_response["data"]
                    if data.get("status") == "error":
                        status, msg = analyze_api_error(data.get("error", ""))
                        return RenewalResult(status, msg)
                    if data.get("status") in ["success", "ok"]:
                        return RenewalResult(RenewalStatus.SUCCESS, "续期成功")
                
                await self.page.wait_for_timeout(3000)
                text = await self.page.text_content("body")
                if "24 час" in text:
                    return RenewalResult(RenewalStatus.RATE_LIMITED, "今日已续期")
                
                return RenewalResult(RenewalStatus.OTHER, "需要验证")
        
        return RenewalResult(RenewalStatus.FAILED, "未找到续约按钮")
    
    async def verify_renewal(self, original_expiry: str) -> Tuple[Optional[str], int]:
        """验证续约结果"""
        await asyncio.sleep(2)
        await self.page.reload(wait_until="networkidle")
        await asyncio.sleep(2)
        
        new_expiry = await self._extract_expiry()
        if not new_expiry:
            return None, 0
        
        if original_expiry and new_expiry:
            old_date = parse_date(original_expiry)
            new_date = parse_date(new_expiry)
            if old_date and new_date:
                return new_expiry, (new_date - old_date).days
        return new_expiry, 0
    
    async def extract_cookies(self) -> Optional[str]:
        """提取Cookie"""
        try:
            cookies = await self.context.cookies()
            castle_cookies = [c for c in cookies if "castle-host.com" in c.get("domain", "")]
            if castle_cookies:
                return "; ".join([f"{c['name']}={c['value']}" for c in castle_cookies])
        except Exception as e:
            logger.error(f"❌ 提取Cookie失败: {e}")
        return None

# ==================== 主流程 ====================

async def run_renewal(config: Config) -> None:
    """执行续约流程"""
    cookies = parse_cookies(config.cookies)
    if not cookies:
        logger.error("❌ Cookie解析失败")
        return
    
    logger.info(f"🔑 已注入 {len(cookies)} 个Cookie")
    
    notifier = Notifier(config.tg_token, config.tg_chat_id)
    github_mgr = GitHubSecretsManager(config.repo_token, config.repository)
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=["--disable-blink-features=AutomationControlled", "--no-sandbox"]
        )
        context = await browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            viewport={"width": 1920, "height": 1080}
        )
        await context.add_cookies(cookies)
        page = await context.new_page()
        page.set_default_timeout(PAGE_TIMEOUT)
        
        client = CastleHostClient(context, page, config.server_id)
        record = RenewalRecord(
            server_id=config.server_id,
            renewal_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            before_expiry="", after_expiry="", status="", message=""
        )
        
        try:
            # 日志中隐藏ID
            masked_id = mask_id(config.server_id)
            logger.info(f"🌐 访问: https://cp.castle-host.com/servers/pay/index/{masked_id}")
            await page.goto(client.url, wait_until="networkidle")
            
            # 检查登录状态
            if "login" in page.url or "auth" in page.url:
                logger.error("❌ Cookie已失效")
                result = RenewalResult(RenewalStatus.FAILED, "Cookie已失效")
                server = ServerInfo(config.server_id, url=client.url)
                await notifier.send(notifier.build_message(server, result))
                return
            
            logger.info("✅ 登录成功")
            
            # 获取服务器信息
            server = await client.get_server_info()
            record.before_expiry = server.expiry_date or ""
            logger.info(f"📅 到期: {server.expiry_formatted}, ⏳ 剩余: {server.days_left} 天")
            
            # 每次都执行续期
            result = await client.renew()
            
            # 验证结果
            if result.status in [RenewalStatus.SUCCESS, RenewalStatus.OTHER]:
                new_expiry, days_added = await client.verify_renewal(server.expiry_date or "")
                if new_expiry and days_added > 0:
                    result = RenewalResult(RenewalStatus.SUCCESS, "续约成功", new_expiry, days_added)
                elif result.status == RenewalStatus.OTHER:
                    result = RenewalResult(RenewalStatus.RATE_LIMITED, "今日已续期")
                record.after_expiry = new_expiry or server.expiry_date or ""
            else:
                record.after_expiry = server.expiry_date or ""
            
            record.status = result.status.value
            record.message = result.message
            
            # 发送通知
            message = notifier.build_message(server, result)
            await notifier.send(message)
            
            # 更新Cookie
            new_cookies = await client.extract_cookies()
            if new_cookies and new_cookies != config.cookies:
                logger.info("🔄 Cookie已变化")
                record.cookie_updated = await github_mgr.update_secret("CASTLE_COOKIES", new_cookies)
            
            # 保存记录
            with open(HISTORY_FILE, "a", encoding="utf-8") as f:
                json.dump(asdict(record), f, ensure_ascii=False)
                f.write("\n")
            
        except Exception as e:
            logger.error(f"❌ 异常: {e}", exc_info=True)
            result = RenewalResult(RenewalStatus.FAILED, str(e))
            server = ServerInfo(config.server_id, url=client.url)
            await notifier.send(notifier.build_message(server, result))
        finally:
            await context.close()
            await browser.close()
            logger.info("👋 完成")

async def main():
    """入口函数"""
    logger.info("=" * 50)
    logger.info("Castle-Host 自动续约")
    logger.info("=" * 50)
    
    config = Config.from_env()
    if not config.cookies:
        logger.error("❌ 未设置 CASTLE_COOKIES")
        sys.exit(1)
    
    await run_renewal(config)

if __name__ == "__main__":
    asyncio.run(main())
