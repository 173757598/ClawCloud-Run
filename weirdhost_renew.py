#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
weirdhost-auto - main.py
功能：使用 Cookie 登录 → 续期 → 提取新 Cookie → 更新 GitHub Secrets
环境变量：
  - REMEMBER_WEB_COOKIE : cookie 值（必须）
  - REMEMBER_WEB_COOKIE_NAME : cookie 名称（可选，默认 'remember_web'）
  - SERVER_URL : 服务器地址（可选）
  - TG_BOT_TOKEN, TG_CHAT_ID : Telegram 通知（可选）
  - REPO_TOKEN : 用于自动更新 GitHub Secrets（可选但推荐）
  - GITHUB_REPOSITORY : 自动由 GitHub Actions 提供
"""
import os
import sys
import time
import asyncio
import aiohttp
import base64
import random
import re
import platform
from datetime import datetime
from urllib.parse import unquote
from typing import Optional, Tuple, Dict

from seleniumbase import SB

try:
    from nacl import encoding, public
    NACL_AVAILABLE = True
except ImportError:
    NACL_AVAILABLE = False

# ============================================================
# 配置
# ============================================================
BASE_URL = "https://hub.weirdhost.xyz/server/"
DOMAIN = "hub.weirdhost.xyz"


# ============================================================
# 工具函数
# ============================================================
def parse_weirdhost_cookie(cookie_str: str) -> Tuple[Optional[str], Optional[str]]:
    if not cookie_str:
        return (None, None)
    cookie_str = cookie_str.strip()
    if "=" in cookie_str:
        parts = cookie_str.split("=", 1)
        if len(parts) == 2:
            return (parts[0].strip(), unquote(parts[1].strip()))
    return (None, None)


def build_server_url(server_id: str) -> Optional[str]:
    if not server_id:
        return None
    server_id = server_id.strip()
    return server_id if server_id.startswith("http") else f"{BASE_URL}{server_id}"


def calculate_remaining_time(expiry_str: str) -> str:
    try:
        for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d"]:
            try:
                expiry_dt = datetime.strptime(expiry_str.strip(), fmt)
                diff = expiry_dt - datetime.now()
                if diff.total_seconds() < 0:
                    return "⚠️ 已过期"
                days = diff.days
                hours = diff.seconds // 3600
                minutes = (diff.seconds % 3600) // 60
                parts = []
                if days > 0:
                    parts.append(f"{days}天")
                if hours > 0:
                    parts.append(f"{hours}小时")
                if minutes > 0 and days == 0:
                    parts.append(f"{minutes}分钟")
                return " ".join(parts) if parts else "不到1分钟"
            except ValueError:
                continue
        return "无法解析"
    except:
        return "计算失败"


def parse_expiry_to_datetime(expiry_str: str) -> Optional[datetime]:
    if not expiry_str or expiry_str == "Unknown":
        return None
    for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d"]:
        try:
            return datetime.strptime(expiry_str.strip(), fmt)
        except ValueError:
            continue
    return None


def random_delay(min_sec: float = 0.5, max_sec: float = 2.0):
    time.sleep(random.uniform(min_sec, max_sec))


# ============================================================
# Telegram 通知
# ============================================================
async def tg_notify(message: str):
    token = os.environ.get("TG_BOT_TOKEN")
    chat_id = os.environ.get("TG_CHAT_ID")
    if not token or not chat_id:
        print("[TG] 未配置")
        return
    async with aiohttp.ClientSession() as session:
        try:
            await session.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                json={"chat_id": chat_id, "text": message, "parse_mode": "HTML"}
            )
            print("[TG] 通知已发送")
        except Exception as e:
            print(f"[TG] 发送失败: {e}")


async def tg_notify_photo(photo_path: str, caption: str = ""):
    token = os.environ.get("TG_BOT_TOKEN")
    chat_id = os.environ.get("TG_CHAT_ID")
    if not token or not chat_id or not os.path.exists(photo_path):
        return
    async with aiohttp.ClientSession() as session:
        try:
            with open(photo_path, "rb") as f:
                data = aiohttp.FormData()
                data.add_field("chat_id", chat_id)
                data.add_field("photo", f, filename=os.path.basename(photo_path))
                data.add_field("caption", caption)
                data.add_field("parse_mode", "HTML")
                await session.post(f"https://api.telegram.org/bot{token}/sendPhoto", data=data)
        except Exception as e:
            print(f"[TG] 图片发送失败: {e}")


def sync_tg_notify(message: str):
    asyncio.run(tg_notify(message))


def sync_tg_notify_photo(photo_path: str, caption: str = ""):
    asyncio.run(tg_notify_photo(photo_path, caption))


# ============================================================
# GitHub Secrets 更新
# ============================================================
def encrypt_secret(public_key: str, secret_value: str) -> str:
    pk = public.PublicKey(public_key.encode("utf-8"), encoding.Base64Encoder())
    sealed_box = public.SealedBox(pk)
    encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
    return base64.b64encode(encrypted).decode("utf-8")


async def update_github_secret(secret_name: str, secret_value: str) -> bool:
    repo_token = os.environ.get("REPO_TOKEN", "").strip()
    repository = os.environ.get("GITHUB_REPOSITORY", "").strip()
    if not repo_token or not repository or not NACL_AVAILABLE:
        return False
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {repo_token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    async with aiohttp.ClientSession() as session:
        try:
            pk_url = f"https://api.github.com/repos/{repository}/actions/secrets/public-key"
            async with session.get(pk_url, headers=headers) as resp:
                if resp.status != 200:
                    return False
                pk_data = await resp.json()
            encrypted_value = encrypt_secret(pk_data["key"], secret_value)
            secret_url = f"https://api.github.com/repos/{repository}/actions/secrets/{secret_name}"
            async with session.put(secret_url, headers=headers, json={"encrypted_value": encrypted_value, "key_id": pk_data["key_id"]}) as resp:
                return resp.status in (201, 204)
        except:
            return False


# ============================================================
# 核心逻辑
# ============================================================
def get_expiry_from_page(sb) -> str:
    """从页面提取到期时间"""
    try:
        page_text = sb.get_page_source()
        
        # 韩文: 유통기한 2026-02-13 00:06:57
        match = re.search(r'유통기한\s*(\d{4}-\d{2}-\d{2}(?:\s+\d{2}:\d{2}:\d{2})?)', page_text)
        if match:
            return match.group(1).strip()
        
        # 英文 Expiry/Expires
        match = re.search(r'Expir(?:y|es?)\s*[:\s]*(\d{4}-\d{2}-\d{2}(?:\s+\d{2}:\d{2}:\d{2})?)', page_text, re.I)
        if match:
            return match.group(1).strip()
        
        # 通用日期格式
        match = re.search(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})', page_text)
        if match:
            return match.group(1).strip()
        
        return "Unknown"
    except:
        return "Unknown"


def detect_turnstile(sb) -> Dict:
    """检测 Turnstile 验证"""
    result = {"found": False, "type": None, "element": None}
    
    # 方法1: 检测 iframe
    try:
        iframes = sb.find_elements("iframe")
        for iframe in iframes:
            src = iframe.get_attribute("src") or ""
            name = iframe.get_attribute("name") or ""
            
            if any(x in src.lower() for x in ["challenge", "turnstile", "cloudflare"]):
                result = {"found": True, "type": "iframe_src", "element": iframe}
                print(f"[*] 检测到 Turnstile iframe (src)")
                return result
            
            if "cf-" in name.lower() or "turnstile" in name.lower():
                result = {"found": True, "type": "iframe_name", "element": iframe}
                print(f"[*] 检测到 Turnstile iframe (name)")
                return result
            
            try:
                size = iframe.size
                if 250 <= size.get('width', 0) <= 350 and 50 <= size.get('height', 0) <= 80:
                    result = {"found": True, "type": "iframe_size", "element": iframe}
                    print(f"[*] 检测到疑似 Turnstile iframe (尺寸: {size})")
                    return result
            except:
                pass
    except Exception as e:
        print(f"[!] iframe 检测异常: {e}")
    
    # 方法2: 检测容器
    try:
        containers = ["[data-sitekey]", ".cf-turnstile", "#cf-turnstile"]
        for selector in containers:
            if sb.is_element_present(selector):
                result = {"found": True, "type": "container", "element": selector}
                print(f"[*] 检测到 Turnstile 容器: {selector}")
                return result
    except:
        pass
    
    # 方法3: JavaScript 检测
    try:
        has_turnstile = sb.execute_script("""
            if (window.turnstile) return 'global';
            const iframes = document.querySelectorAll('iframe');
            for (let iframe of iframes) {
                const src = iframe.src || '';
                if (src.includes('challenge') || src.includes('turnstile')) return 'iframe';
            }
            return null;
        """)
        if has_turnstile:
            result = {"found": True, "type": f"js_{has_turnstile}", "element": None}
            print(f"[*] 通过 JS 检测到 Turnstile: {has_turnstile}")
            return result
    except:
        pass
    
    return result


def handle_turnstile(sb, max_attempts: int = 3) -> bool:
    """处理 Turnstile 验证"""
    detection = detect_turnstile(sb)
    
    if not detection["found"]:
        print("[*] 未检测到 Turnstile")
        return True
    
    print(f"[*] Turnstile 类型: {detection['type']}")
    
    for attempt in range(max_attempts):
        print(f"\n[*] Turnstile 处理尝试 {attempt + 1}/{max_attempts}")
        
        try:
            print("[*] 尝试 UC GUI 点击...")
            sb.uc_gui_click_captcha()
            time.sleep(3)
            
            new_detection = detect_turnstile(sb)
            if not new_detection["found"]:
                print("[+] Turnstile 已通过")
                return True
        except Exception as e:
            print(f"[!] UC GUI 失败: {e}")
        
        time.sleep(2)
    
    print("[!] Turnstile 处理可能未成功")
    return False


def find_and_click_renew_button(sb) -> bool:
    """查找并点击续期按钮"""
    button_texts = ["시간추가", "Add Time", "Renew", "续期", "연장"]
    
    for text in button_texts:
        try:
            selector = f"button:contains('{text}')"
            if sb.is_element_visible(selector):
                print(f"[*] 找到按钮: {text}")
                random_delay(0.5, 1.0)
                sb.click(selector)
                return True
        except:
            pass
        
        try:
            xpath = f"//button[contains(text(), '{text}')]"
            if sb.is_element_present(xpath):
                print(f"[*] 通过 XPath 找到按钮: {text}")
                random_delay(0.5, 1.0)
                sb.click(xpath)
                return True
        except:
            pass
        
        try:
            xpath = f"//a[contains(text(), '{text}')]"
            if sb.is_element_present(xpath):
                print(f"[*] 找到链接按钮: {text}")
                random_delay(0.5, 1.0)
                sb.click(xpath)
                return True
        except:
            pass
    
    return False


def check_modal_result(sb) -> Dict:
    """
    检查模态框/弹窗中的结果
    点击按钮后，通常会弹出确认框或结果提示
    """
    result = {"success": None, "message": "", "is_cooldown": False, "needs_confirm": False}
    
    print("[*] 检查弹窗/模态框...")
    
    # 等待模态框出现
    time.sleep(2)
    
    try:
        page_source = sb.get_page_source()
        page_lower = page_source.lower()
        
        # 检测模态框
        modal_selectors = [
            ".modal",
            "[role='dialog']",
            ".popup",
            ".alert",
            ".swal2-container",  # SweetAlert2
            ".toast"
        ]
        
        modal_found = False
        for selector in modal_selectors:
            if sb.is_element_present(selector):
                modal_found = True
                print(f"[*] 检测到模态框: {selector}")
                break
        
        # 检测冷却期消息
        cooldown_patterns = [
            r"can only.*once",
            r"already.*renew",
            r"cannot renew",
            r"too soon",
            r"wait.*hour",
            r"wait.*minute",
            r"한 번만",
            r"이미.*갱신",
            r"갱신.*불가",
            r"시간.*남음",
        ]
        for pattern in cooldown_patterns:
            if re.search(pattern, page_lower):
                result["is_cooldown"] = True
                result["message"] = "冷却期内，暂无法续期"
                print(f"[*] 检测到冷却期: {pattern}")
                return result
        
        # 检测需要确认（Turnstile 验证）
        if "turnstile" in page_lower or detect_turnstile(sb)["found"]:
            result["needs_confirm"] = True
            result["message"] = "需要 Turnstile 验证"
            print("[*] 检测到需要 Turnstile 验证")
            return result
        
        # 检测成功消息
        success_patterns = [
            r"success",
            r"완료",  # 完成
            r"갱신.*성공",  # 续期成功
            r"시간.*추가",  # 时间添加
            r"extended",
            r"renewed",
        ]
        for pattern in success_patterns:
            if re.search(pattern, page_lower):
                result["success"] = True
                result["message"] = "检测到成功标志"
                print(f"[*] 检测到成功: {pattern}")
                return result
        
        # 检测错误消息
        error_patterns = [
            r"error",
            r"fail",
            r"실패",
            r"오류",
        ]
        for pattern in error_patterns:
            match = re.search(rf'.{{0,30}}{pattern}.{{0,30}}', page_lower)
            if match:
                result["success"] = False
                result["message"] = f"检测到错误: {match.group(0)[:50]}"
                print(f"[!] {result['message']}")
                return result
        
        if modal_found:
            result["message"] = "检测到模态框，但无法确定结果"
        else:
            result["message"] = "未检测到明确的结果提示"
        
    except Exception as e:
        result["message"] = f"检查异常: {e}"
        print(f"[!] {result['message']}")
    
    return result


def navigate_to_server_page(sb, server_url: str, cookie_name: str, cookie_value: str) -> bool:
    """
    导航到服务器页面（带重试和 Cookie 恢复）
    """
    max_retries = 3
    
    for retry in range(max_retries):
        print(f"\n[*] 导航到服务器页面 (尝试 {retry + 1}/{max_retries})")
        
        # 确保 Cookie 存在
        try:
            sb.add_cookie({
                "name": cookie_name,
                "value": cookie_value,
                "domain": DOMAIN,
                "path": "/"
            })
        except:
            pass
        
        # 访问页面
        sb.uc_open_with_reconnect(server_url, reconnect_time=5)
        time.sleep(3)
        
        # 处理 Turnstile
        handle_turnstile(sb, max_attempts=2)
        time.sleep(2)
        
        # 检查是否在正确的页面
        current_url = sb.get_current_url()
        
        if "/login" in current_url:
            print("[!] 需要登录，Cookie 可能已失效")
            return False
        
        if "/server/" in current_url:
            # 验证页面内容
            expiry = get_expiry_from_page(sb)
            if expiry != "Unknown":
                print(f"[+] 成功到达服务器页面，到期时间: {expiry}")
                return True
            else:
                print("[!] 页面内容异常，重试...")
        else:
            print(f"[!] 页面跳转到: {current_url}，重试...")
        
        time.sleep(2)
    
    return False


def verify_renewal_result(sb, server_url: str, cookie_name: str, cookie_value: str, original_expiry: str) -> Dict:
    """
    验证续期结果 - 改进版
    不使用 refresh()，而是重新导航到页面
    """
    result = {"success": False, "new_expiry": None, "message": ""}
    
    print("\n[*] 验证续期结果...")
    print("[*] 重新导航到服务器页面...")
    
    # 等待一下让服务器处理
    time.sleep(3)
    
    # 重新导航到服务器页面
    if not navigate_to_server_page(sb, server_url, cookie_name, cookie_value):
        result["message"] = "无法重新访问服务器页面"
        return result
    
    # 获取新的到期时间
    new_expiry = get_expiry_from_page(sb)
    result["new_expiry"] = new_expiry
    
    print(f"[*] 原到期时间: {original_expiry}")
    print(f"[*] 新到期时间: {new_expiry}")
    
    # 比较时间
    original_dt = parse_expiry_to_datetime(original_expiry)
    new_dt = parse_expiry_to_datetime(new_expiry)
    
    if original_dt and new_dt:
        if new_dt > original_dt:
            diff = new_dt - original_dt
            diff_hours = diff.total_seconds() / 3600
            result["success"] = True
            result["message"] = f"到期时间延长了 {diff_hours:.1f} 小时"
            print(f"[+] {result['message']}")
        elif new_dt == original_dt:
            result["message"] = "到期时间未变化（可能在冷却期内）"
            print(f"[*] {result['message']}")
        else:
            result["message"] = "到期时间异常"
            print(f"[!] {result['message']}")
    elif new_expiry != "Unknown":
        result["new_expiry"] = new_expiry
        result["message"] = f"获取到新时间: {new_expiry}，但无法与原时间比较"
    else:
        result["message"] = "无法获取新的到期时间"
        print(f"[!] {result['message']}")
    
    return result


def add_server_time():
    """主函数"""
    # 解析环境变量
    weirdhost_cookie = os.environ.get("WEIRDHOST_COOKIE", "").strip()
    weirdhost_id = os.environ.get("WEIRDHOST_ID", "").strip()
    
    cookie_name, cookie_value = parse_weirdhost_cookie(weirdhost_cookie)
    server_url = build_server_url(weirdhost_id)
    
    if not cookie_name or not cookie_value:
        sync_tg_notify("🎁 <b>Weirdhost 续订报告</b>\n\n❌ WEIRDHOST_COOKIE 未设置或格式错误")
        return
    
    if not server_url:
        sync_tg_notify("🎁 <b>Weirdhost 续订报告</b>\n\n❌ WEIRDHOST_ID 未设置")
        return
    
    print("=" * 60)
    print("Weirdhost 自动续期 v3")
    print("=" * 60)
    print(f"[*] Cookie: {cookie_name}")
    print(f"[*] URL: {server_url}")
    print(f"[*] 系统: {platform.system()}")
    print("=" * 60)
    
    original_expiry = "Unknown"
    
    try:
        with SB(uc=True, test=True, locale="en", headless=False) as sb:
            print("\n[*] 浏览器已启动")
            
            # 访问域名并设置 Cookie
            print(f"[*] 访问: https://{DOMAIN}")
            sb.uc_open_with_reconnect(f"https://{DOMAIN}", reconnect_time=5)
            time.sleep(2)
            handle_turnstile(sb)
            
            # 设置 Cookie
            print(f"[*] 设置 Cookie")
            sb.add_cookie({
                "name": cookie_name,
                "value": cookie_value,
                "domain": DOMAIN,
                "path": "/"
            })
            
            # 导航到服务器页面
            if not navigate_to_server_page(sb, server_url, cookie_name, cookie_value):
                sb.save_screenshot("login_failed.png")
                sync_tg_notify_photo("login_failed.png", "🎁 <b>Weirdhost</b>\n\n❌ 无法访问服务器页面，Cookie 可能已失效")
                return
            
            print("[+] 登录成功")
            
            # 获取当前到期时间
            original_expiry = get_expiry_from_page(sb)
            remaining = calculate_remaining_time(original_expiry)
            print(f"[*] 到期时间: {original_expiry}")
            print(f"[*] 剩余: {remaining}")
            
            sb.save_screenshot("before_renew.png")
            
            # 点击续期按钮
            print("\n" + "=" * 50)
            print("[*] 开始续期")
            print("=" * 50)
            
            random_delay(1.0, 2.0)
            
            if not find_and_click_renew_button(sb):
                sb.save_screenshot("no_button.png")
                sync_tg_notify_photo("no_button.png", f"🎁 <b>Weirdhost</b>\n\n⚠️ 未找到续期按钮\n📅 到期: {original_expiry}\n⏳ 剩余: {remaining}")
                return
            
            print("[+] 已点击续期按钮")
            time.sleep(2)
            sb.save_screenshot("after_click.png")
            
            # 检查模态框结果
            modal_result = check_modal_result(sb)
            
            if modal_result["is_cooldown"]:
                # 冷却期
                sb.save_screenshot("cooldown.png")
                msg = f"""🎁 <b>Weirdhost 续订报告</b>

ℹ️ 暂无需续期（冷却期内）
📅 到期: {original_expiry}
⏳ 剩余: {remaining}"""
                print(f"\n[*] {modal_result['message']}")
                sync_tg_notify(msg)
                return
            
            if modal_result["needs_confirm"]:
                # 需要 Turnstile 验证
                print("\n[*] 处理 Turnstile 验证...")
                handle_turnstile(sb, max_attempts=3)
                time.sleep(2)
                
                # 处理确认复选框
                try:
                    checkbox_selectors = [
                        'input[type="checkbox"]:not([disabled])',
                        '.modal input[type="checkbox"]',
                        '[role="dialog"] input[type="checkbox"]'
                    ]
                    for selector in checkbox_selectors:
                        if sb.is_element_visible(selector):
                            print(f"[*] 点击复选框: {selector}")
                            random_delay(0.3, 0.8)
                            sb.click(selector)
                            time.sleep(1)
                            break
                except:
                    pass
                
                # 处理确认按钮
                try:
                    confirm_texts = ["확인", "Confirm", "OK", "Submit", "Yes"]
                    for text in confirm_texts:
                        try:
                            btn = f"button:contains('{text}')"
                            if sb.is_element_visible(btn):
                                print(f"[*] 点击确认: {text}")
                                random_delay(0.3, 0.8)
                                sb.click(btn)
                                time.sleep(2)
                                break
                        except:
                            pass
                except:
                    pass
            
            time.sleep(3)
            sb.save_screenshot("after_confirm.png")
            
            # 再次检查结果
            final_modal_result = check_modal_result(sb)
            
            if final_modal_result["is_cooldown"]:
                msg = f"""🎁 <b>Weirdhost 续订报告</b>

ℹ️ 暂无需续期（冷却期内）
📅 到期: {original_expiry}
⏳ 剩余: {remaining}"""
                print(f"\n[*] {final_modal_result['message']}")
                sync_tg_notify(msg)
                return
            
            # 验证续期结果（通过重新访问页面比较时间）
            time_result = verify_renewal_result(sb, server_url, cookie_name, cookie_value, original_expiry)
            
            sb.save_screenshot("final_state.png")
            
            # 综合判断结果
            new_expiry = time_result["new_expiry"] or original_expiry
            new_remaining = calculate_remaining_time(new_expiry)
            
            if time_result["success"]:
                # 时间确实延长了
                msg = f"""🎁 <b>Weirdhost 续订报告</b>

✅ 续期成功！
📅 新到期: {new_expiry}
⏳ 剩余: {new_remaining}
📝 {time_result['message']}"""
                print(f"\n[+] 续期成功！")
                sync_tg_notify(msg)
            
            elif "未变化" in time_result["message"]:
                # 时间未变化，可能是冷却期
                msg = f"""🎁 <b>Weirdhost 续订报告</b>

ℹ️ 到期时间未变化（可能在冷却期内）
📅 到期: {original_expiry}
⏳ 剩余: {remaining}"""
                print(f"\n[*] 时间未变化")
                sync_tg_notify(msg)
            
            else:
                # 状态未知
                msg = f"""🎁 <b>Weirdhost 续订报告</b>

⚠️ 续期状态未知
📅 到期: {new_expiry}
⏳ 剩余: {new_remaining}
📝 {time_result['message']}"""
                print(f"\n[?] 状态未知")
                sync_tg_notify_photo("final_state.png", msg)
            
            # 尝试更新 Cookie
            try:
                cookies = sb.get_cookies()
                for cookie in cookies:
                    if cookie.get("name", "").startswith("remember_web"):
                        new_cookie_value = cookie.get("value", "")
                        if new_cookie_value and new_cookie_value != cookie_value:
                            new_cookie_str = f"{cookie['name']}={new_cookie_value}"
                            print(f"\n[*] 检测到新 Cookie")
                            updated = asyncio.run(update_github_secret("WEIRDHOST_COOKIE", new_cookie_str))
                            if updated:
                                print("[+] Cookie 已更新到 GitHub Secrets")
                            break
            except Exception as e:
                print(f"[!] Cookie 更新失败: {e}")
    
    except Exception as e:
        import traceback
        error_msg = f"🎁 <b>Weirdhost 续订报告</b>\n\n❌ 运行异常\n\n<code>{repr(e)}</code>"
        print(f"\n[!] 异常: {repr(e)}")
        traceback.print_exc()
        
        try:
            if os.path.exists("final_state.png"):
                sync_tg_notify_photo("final_state.png", error_msg)
            elif os.path.exists("after_click.png"):
                sync_tg_notify_photo("after_click.png", error_msg)
            elif os.path.exists("before_renew.png"):
                sync_tg_notify_photo("before_renew.png", error_msg)
            else:
                sync_tg_notify(error_msg)
        except:
            sync_tg_notify(error_msg)


# ============================================================
# 入口
# ============================================================
if __name__ == "__main__":
    add_server_time()
