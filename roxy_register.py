"""
RoxyBrowser 指纹浏览器注册模块
通过 RoxyBrowser 本地 API 创建/管理指纹浏览器窗口，使用 Playwright CDP 连接进行自动注册。
相比 Playwright + Stealth 方案，指纹浏览器的 TES 通过率更高。
"""
import asyncio
import json
import time
import secrets
import hashlib
import base64
import os
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlencode, urlparse

import re
import requests as _requests

from kiro_register import (
    _generate_password, _generate_name,
    _dismiss_cookie, _b64url, _sha1_hash,
    persist_tokens, inject_machine_ids, skip_onboarding,
    REG_OIDC, REG_SCOPES, REG_REDIRECT_URI, KIRO_SIGNIN_URL, ISSUER_URL,
)

import random as _random


class _RequestsMailClient:
    """使用标准 requests 库的邮件客户端，避免 curl_cffi SSL 问题"""

    def __init__(self, base_url: str, api_key: str, domain_id=None):
        self.base_url = base_url.rstrip("/")
        self.domain_id = int(domain_id) if domain_id and str(domain_id).isdigit() else 0
        self.session = _requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        })
        self.mailbox_id = None
        self.address = None

    def create_mailbox(self) -> str:
        resp = self.session.post(
            f"{self.base_url}/api/v1/mailboxes",
            json={"domainId": self.domain_id, "expiresInHours": 3},
            timeout=15,
        )
        if resp.status_code != 200 and resp.status_code != 201:
            raise RuntimeError(f"邮箱创建失败: HTTP {resp.status_code} - {resp.text[:200]}")
        data = resp.json()
        if "id" not in data:
            raise RuntimeError(f"邮箱创建返回异常: {resp.text[:200]}")
        self.mailbox_id = data["id"]
        self.address = data["address"]
        return self.address

    def wait_otp(self, timeout: int = 120, poll_interval: int = 3) -> str:
        deadline = time.time() + timeout
        while time.time() < deadline:
            resp = self.session.get(
                f"{self.base_url}/api/v1/mailboxes/{self.mailbox_id}/messages",
                timeout=10,
            )
            if resp.status_code == 200:
                messages = resp.json()
                items = messages.get("items", []) if isinstance(messages, dict) else messages
                if items:
                    msg_id = items[0]["id"]
                    ext_resp = self.session.get(
                        f"{self.base_url}/api/v1/mailboxes/{self.mailbox_id}/messages/{msg_id}/extractions",
                        timeout=10,
                    )
                    if ext_resp.status_code == 200:
                        extractions = ext_resp.json()
                        ext_items = extractions.get("items", extractions) if isinstance(extractions, dict) else extractions
                        if isinstance(ext_items, list):
                            for ext in ext_items:
                                val = ext.get("value", "")
                                if re.match(r'^\d{6}$', val):
                                    return val
                    detail_resp = self.session.get(
                        f"{self.base_url}/api/v1/mailboxes/{self.mailbox_id}/messages/{msg_id}",
                        timeout=10,
                    )
                    if detail_resp.status_code == 200:
                        detail = detail_resp.json()
                        body = detail.get("body", "") or detail.get("textBody", "") or detail.get("htmlBody", "") or str(detail)
                        match = re.search(r'\b(\d{6})\b', body)
                        if match:
                            return match.group(1)
            time.sleep(poll_interval)
        return ""


class RoxyBrowser:
    """RoxyBrowser 本地 API 客户端"""

    def __init__(self, api_key: str, port: int = 50000):
        self.base_url = f"http://127.0.0.1:{port}"
        self.headers = {
            "Content-Type": "application/json",
            "token": api_key,
        }

    def health(self) -> bool:
        try:
            r = _requests.get(f"{self.base_url}/health", headers=self.headers, timeout=5)
            return r.status_code == 200 and r.json().get("code") == 0
        except Exception:
            return False

    def list_workspaces(self) -> list:
        r = _requests.get(f"{self.base_url}/browser/workspace", headers=self.headers, timeout=30)
        data = r.json()
        if data.get("code") == 0:
            return data.get("data", {}).get("rows", []) or data.get("data", {}).get("list", [])
        return []

    def list_windows(self, workspace_id: int) -> list:
        r = _requests.get(
            f"{self.base_url}/browser/list?workspaceId={workspace_id}",
            headers=self.headers, timeout=30
        )
        data = r.json()
        if data.get("code") == 0:
            return data.get("data", {}).get("rows", []) or data.get("data", {}).get("list", [])
        return []

    def create_window(self, workspace_id: int, name: str = "", proxy_info: dict = None) -> str | None:
        payload = {
            "workspaceId": workspace_id,
            "windowName": name or f"kiro_reg_{int(time.time())}",
            "coreVersion": "135",
            "os": "Windows",
            "fingerInfo": {
                "randomFingerprint": True,
                "canvas": True, "audioContext": True, "webGL": True,
                "webGLInfo": True, "clientRects": True, "deviceInfo": True,
                "deviceNameSwitch": True, "macInfo": True, "doNotTrack": True,
                "portScanProtect": True, "webRTC": 2, "webGpu": "webgl",
                "isLanguageBaseIp": True, "isTimeZone": True,
                "isPositionBaseIp": True, "position": 1, "openBattery": True,
                "clearCacheFile": True, "clearCookie": True,
                "clearLocalStorage": True, "syncCookie": True,
                "syncPassword": True, "syncTab": True,
            },
        }
        if proxy_info:
            payload["proxyInfo"] = proxy_info
        r = _requests.post(f"{self.base_url}/browser/create", headers=self.headers, json=payload, timeout=15)
        data = r.json()
        if data.get("code") == 0:
            return data.get("data", {}).get("dirId")
        return None

    def open_window(self, workspace_id: int, dir_id: str, headless: bool = False) -> dict | None:
        payload = {"workspaceId": workspace_id, "dirId": dir_id, "headless": headless}
        r = _requests.post(f"{self.base_url}/browser/open", headers=self.headers, json=payload, timeout=60)
        data = r.json()
        if data.get("code") == 0:
            return data.get("data", {})
        return None

    def close_window(self, dir_id: str) -> bool:
        r = _requests.post(
            f"{self.base_url}/browser/close", headers=self.headers,
            json={"dirId": dir_id}, timeout=10
        )
        return r.json().get("code") == 0

    def delete_window(self, workspace_id: int, dir_id: str) -> bool:
        r = _requests.post(
            f"{self.base_url}/browser/delete", headers=self.headers,
            json={"workspaceId": workspace_id, "dirIds": [dir_id]}, timeout=10
        )
        return r.json().get("code") == 0

    def randomize_fingerprint(self, workspace_id: int, dir_id: str) -> bool:
        r = _requests.post(
            f"{self.base_url}/browser/random_env", headers=self.headers,
            json={"workspaceId": workspace_id, "dirId": dir_id}, timeout=10
        )
        return r.json().get("code") == 0

    def clear_cache(self, workspace_id: int, dir_id: str) -> bool:
        ok1 = ok2 = False
        try:
            r = _requests.post(
                f"{self.base_url}/browser/clear_local_cache", headers=self.headers,
                json={"dirIds": [dir_id]}, timeout=10
            )
            ok1 = r.json().get("code") == 0
        except Exception:
            pass
        try:
            r = _requests.post(
                f"{self.base_url}/browser/clear_server_cache", headers=self.headers,
                json={"workspaceId": workspace_id, "dirIds": [dir_id]}, timeout=10
            )
            ok2 = r.json().get("code") == 0
        except Exception:
            pass
        return ok1 or ok2


_workspace_round_robin_index = 0


async def register_with_roxy(
    api_key: str = "",
    port: int = 50000,
    headless: bool = False,
    auto_login: bool = True,
    skip_onboard: bool = True,
    mail_url: str = None,
    mail_key: str = None,
    mail_domain_id=None,
    mail_provider_instance=None,
    proxy_info: dict = None,
    delete_after: bool = True,
    log=print,
    cancel_check=None,
):
    """使用 RoxyBrowser 指纹浏览器完成 Kiro 自动注册。"""
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    from playwright.async_api import async_playwright

    if cancel_check and cancel_check():
        return None

    # ─── 初始化 RoxyBrowser ─────────────────────────────────────────────
    roxy = RoxyBrowser(api_key, port)
    if not roxy.health():
        log("RoxyBrowser 未运行或 API 不可达!", "err")
        return None

    log("RoxyBrowser 连接成功", "ok")

    workspaces = roxy.list_workspaces()
    if not workspaces:
        log("未找到工作空间", "err")
        return None
    workspace_id = workspaces[0].get("id") or workspaces[0].get("workspaceId")

    all_windows = roxy.list_windows(workspace_id)
    if not all_windows:
        log("未找到浏览器窗口", "err")
        return None

    closed_windows = [w for w in all_windows if w.get("openStatus") == 0]
    if not closed_windows:
        log("所有窗口都在使用中", "err")
        return None

    global _workspace_round_robin_index
    win_idx = _workspace_round_robin_index % len(closed_windows)
    _workspace_round_robin_index += 1
    chosen = closed_windows[win_idx]
    dir_id = chosen.get("dirId")
    win_name = chosen.get("windowName", "")
    log(f"使用窗口: {win_name} [{win_idx+1}/{len(closed_windows)}]")

    created_new = False
    roxy.randomize_fingerprint(workspace_id, dir_id)
    roxy.clear_cache(workspace_id, dir_id)
    log("已随机化指纹并清除缓存", "ok")

    open_data = roxy.open_window(workspace_id, dir_id, headless=headless)
    if not open_data:
        log("打开浏览器窗口失败!", "err")
        return None

    ws_url = open_data.get("ws") or open_data.get("webSocketDebuggerUrl") or open_data.get("wsEndpoint")
    if not ws_url:
        log(f"未获取到 WebSocket URL!", "err")
        roxy.close_window(dir_id)
        return None
    log(f"CDP 连接: {ws_url[:60]}...", "ok")

    # ─── 准备注册信息 ───────────────────────────────────────────────────
    s = _requests.Session()
    s.verify = False

    if mail_provider_instance and not isinstance(mail_provider_instance, _RequestsMailClient):
        mail = _RequestsMailClient(
            base_url=getattr(mail_provider_instance, 'base_url', mail_url or ""),
            api_key=getattr(mail_provider_instance, 'api_key', mail_key or ""),
            domain_id=getattr(mail_provider_instance, 'domain_id', mail_domain_id),
        )
    elif mail_provider_instance:
        mail = mail_provider_instance
    else:
        mail = _RequestsMailClient(base_url=mail_url, api_key=mail_key, domain_id=mail_domain_id)
    try:
        email = mail.create_mailbox()
    except Exception as e:
        log(f"邮箱创建失败: {e}", "err")
        roxy.close_window(dir_id)
        return None
    password = _generate_password()
    full_name = _generate_name()
    log(f"邮箱: {email}", "ok")
    log(f"密码: {password[:4]}****")
    log(f"姓名: {full_name}")

    def _partial_result(reason="unknown"):
        return {
            "email": email, "password": password, "full_name": full_name,
            "provider": "BuilderId", "authMethod": "IdC", "region": "us-east-1",
            "accessToken": "", "refreshToken": "",
            "incomplete": True, "failReason": reason, "browser": "RoxyBrowser",
        }

    def _cleanup():
        try:
            roxy.close_window(dir_id)
        except Exception:
            pass
        try:
            roxy.randomize_fingerprint(workspace_id, dir_id)
            roxy.clear_cache(workspace_id, dir_id)
        except Exception:
            pass

    # ─── Phase 1: OIDC 客户端注册 ──────────────────────────────────────
    log("阶段 1: OIDC 客户端注册")
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = _b64url(hashlib.sha256(code_verifier.encode()).digest())
    state_val = secrets.token_urlsafe(32)

    reg_resp = None
    for _reg_retry in range(3):
        try:
            reg_resp = s.post(f"{REG_OIDC}/client/register", json={
                "clientName": "Kiro IDE", "clientType": "public",
                "grantTypes": ["authorization_code", "refresh_token"],
                "issuerUrl": ISSUER_URL,
                "redirectUris": [REG_REDIRECT_URI], "scopes": REG_SCOPES,
            }, timeout=30, verify=False)
            break
        except Exception:
            if _reg_retry < 2:
                time.sleep(3)
            else:
                log("OIDC 注册连接失败", "err")
                _cleanup()
                return _partial_result("OIDC注册连接失败")
    reg = reg_resp.json()
    if "clientId" not in reg:
        log(f"OIDC 注册失败: {reg}", "err")
        _cleanup()
        return _partial_result("OIDC注册失败")
    client_id = reg["clientId"]
    client_secret = reg["clientSecret"]
    log("OIDC 客户端注册成功", "ok")

    signin_url = f"{KIRO_SIGNIN_URL}?" + urlencode({
        "state": state_val, "code_challenge": code_challenge,
        "code_challenge_method": "S256", "redirect_uri": REG_REDIRECT_URI,
        "redirect_from": "KiroIDE",
    })
# === PLACEHOLDER_PHASE2 ===
    # ─── Phase 2: CDP 连接 ────────────────────────────────────────────────
    log("阶段 2: 启动浏览器")
    authorization_code = ""
    signin_callback_params = {}

    try:
        async with async_playwright() as p:
            browser = None
            for _cdp_retry in range(5):
                try:
                    browser = await p.chromium.connect_over_cdp(ws_url)
                    break
                except Exception:
                    await asyncio.sleep(2)
            if not browser:
                log("CDP 连接失败!", "err")
                _cleanup()
                return _partial_result("CDP连接失败")
            contexts = browser.contexts
            context = contexts[0] if contexts else await browser.new_context()
            await context.clear_cookies()
            pages = context.pages
            page = pages[0] if pages else await context.new_page()
            log("CDP 浏览器已连接", "ok")

            async def _js_click_submit():
                """用 JS 找到并点击提交/继续按钮"""
                await page.evaluate("""() => {
                    const buttons = Array.from(document.querySelectorAll('button'));
                    const visible = buttons.filter(b => b.offsetWidth > 0 && b.offsetHeight > 0);
                    for (const b of visible) {
                        const t = (b.innerText || '').toLowerCase();
                        if (t.includes('continue') || t.includes('next') || t.includes('submit') || t.includes('verify')) {
                            b.click(); return;
                        }
                    }
                    if (visible.length > 0) visible[visible.length - 1].click();
                }""")

            # route 拦截作为备份（本地服务器是主要方式）
            async def _route_intercept(route):
                nonlocal authorization_code, signin_callback_params
                url = route.request.url
                parsed = urlparse(url)
                qs = parse_qs(parsed.query)
                code = qs.get("code", [""])[0]
                if code and not authorization_code:
                    authorization_code = code
                    log("已拦截授权码 (route)", "ok")
                elif "signin/callback" in parsed.path or qs.get("login_option"):
                    if not signin_callback_params:
                        signin_callback_params = {k: v[0] for k, v in qs.items()}
                await route.continue_()

            await page.route("**/127.0.0.1:3128**", _route_intercept)
            await page.route("**/localhost:3128**", _route_intercept)

            # CDP Network 监听兜底
            cdp_session = await context.new_cdp_session(page)
            await cdp_session.send("Network.enable")

            def _on_cdp_request(params):
                nonlocal authorization_code
                if authorization_code:
                    return
                req_url = params.get("request", {}).get("url", "")
                if ("127.0.0.1:3128" in req_url or "localhost:3128" in req_url) and "code=" in req_url:
                    qs = parse_qs(urlparse(req_url).query)
                    code = qs.get("code", [""])[0]
                    if code:
                        authorization_code = code
                        log("已拦截授权码 (CDP)", "ok")
                redir = params.get("redirectResponse", {}).get("headers", {})
                location = redir.get("Location", "") or redir.get("location", "")
                if location and "code=" in location and "127.0.0.1:3128" in location:
                    qs = parse_qs(urlparse(location).query)
                    code = qs.get("code", [""])[0]
                    if code:
                        authorization_code = code
                        log("已拦截授权码 (CDP redirect)", "ok")

            cdp_session.on("Network.requestWillBeSent", _on_cdp_request)

            # 导航到 Kiro signin
            await page.goto(signin_url, timeout=60000, wait_until="domcontentloaded")
            await asyncio.sleep(3)
            await _dismiss_cookie(page)

            # 点击 AWS Builder ID 按钮
            if "app.kiro.dev" in page.url:
                log("正在选择登录方式...")
                await asyncio.sleep(2)
                for sel in [
                    'xpath=//*[@id="layout-viewport"]/div/div/div/div[2]/div/div[1]/button[3]',
                    'xpath=//button[contains(text(),"AWS Builder ID")]',
                    'xpath=//button[contains(text(),"Builder ID")]',
                    'xpath=//button[contains(text(),"Sign in")]',
                ]:
                    loc = page.locator(sel)
                    try:
                        if await loc.count() > 0 and await loc.first.is_visible():
                            await loc.first.click()
                            log("已点击登录按钮", "ok")
                            break
                    except Exception:
                        pass
                await asyncio.sleep(3)
                for _ in range(20):
                    if signin_callback_params:
                        break
                    await asyncio.sleep(1)

            # 构造 authorize URL 并让浏览器导航
            if signin_callback_params and not authorization_code:
                log("正在跳转到授权页面...")
                authorize_url = f"{REG_OIDC}/authorize?" + urlencode({
                    "response_type": "code", "client_id": client_id,
                    "redirect_uri": REG_REDIRECT_URI,
                    "scopes": ",".join(REG_SCOPES),
                    "state": state_val, "code_challenge": code_challenge,
                    "code_challenge_method": "S256",
                })
                try:
                    await page.goto(authorize_url, timeout=60000, wait_until="domcontentloaded")
                except Exception:
                    pass
                await asyncio.sleep(3)
# === PLACEHOLDER_PHASE3 ===

            # 等待到达 signin.aws 或 profile.aws
            for _ in range(15):
                if "signin.aws" in page.url or "profile.aws" in page.url:
                    break
                if authorization_code:
                    break
                await asyncio.sleep(2)
            await asyncio.sleep(2)

            # 如果在 signin.aws，输入邮箱
            if "signin.aws" in page.url and not authorization_code:
                email_input = page.locator('xpath=//input[@type="email"]')
                if await email_input.count() == 0:
                    email_input = page.locator('xpath=//input[@type="text"]').first
                if await email_input.count() > 0:
                    await email_input.first.fill(email)
                    log(f"邮箱已填入: {email}", "ok")
                    await asyncio.sleep(0.5)
                    await _js_click_submit()
                    await asyncio.sleep(4)

            # 等待 profile.aws
            if not authorization_code:
                for _ in range(15):
                    if "profile.aws" in page.url:
                        break
                    if authorization_code:
                        break
                    await asyncio.sleep(2)
                await asyncio.sleep(2)

            # ─── 状态机（对齐 kiro_register.py 的元素检测逻辑）────────────
            async def detect_state():
                nonlocal authorization_code
                if authorization_code:
                    return "DONE"
                url = page.url
                if "127.0.0.1:3128" in url or "localhost:3128" in url:
                    qs = parse_qs(urlparse(url).query)
                    code = qs.get("code", [""])[0]
                    if code:
                        authorization_code = code
                        return "DONE"
                    return "CALLBACK"
                if "chrome-error" in url:
                    return "CALLBACK"
                try:
                    result = await page.evaluate("""() => {
                        const url = location.href;
                        const pwds = document.querySelectorAll('input[type="password"]');
                        const visiblePwds = Array.from(pwds).filter(e => e.offsetWidth > 0);
                        const nameInput = document.querySelector('input[placeholder*="Silva"]');
                        const otpInput = document.querySelector('input[inputmode="numeric"]') ||
                                         document.querySelector('input[autocomplete="one-time-code"]') ||
                                         document.querySelector('input[name*="otp"]') ||
                                         document.querySelector('input[name*="code"]') ||
                                         document.querySelector('input[placeholder*="6-digit"]') ||
                                         document.querySelector('input[placeholder*="digit"]');
                        const emailInput = document.querySelector('input[type="email"]');
                        const buttons = Array.from(document.querySelectorAll('button'));
                        const visibleBtns = buttons.filter(b => b.offsetWidth > 0 && b.offsetHeight > 0);
                        const hasConsentBtn = visibleBtns.some(b => {
                            const t = (b.innerText || '').toLowerCase();
                            return t.includes('allow') || t.includes('authorize') ||
                                   t.includes('accept') || t.includes('confirm');
                        });
                        const hasAnyInput = document.querySelectorAll('input:not([type="hidden"])').length > 0;
                        const hasAnyButton = visibleBtns.length > 0;
                        const isLoading = !hasAnyInput && !hasAnyButton;
                        return {
                            url, visiblePwdCount: visiblePwds.length,
                            hasName: !!(nameInput && nameInput.offsetWidth > 0),
                            hasOtp: !!(otpInput && otpInput.offsetWidth > 0),
                            hasEmail: !!(emailInput && emailInput.offsetWidth > 0),
                            hasConsentBtn, isLoading,
                        };
                    }""")
                except Exception:
                    return "UNKNOWN"
                if "chrome-error" in result["url"]:
                    return "CALLBACK"
                if result["visiblePwdCount"] >= 1:
                    return "PASSWORD"
                if result["hasOtp"]:
                    return "OTP"
                if result["hasName"]:
                    return "NAME"
                if result["hasEmail"]:
                    return "EMAIL"
                if "awsapps.com" in result["url"] and result["hasConsentBtn"]:
                    return "CONSENT"
                if "profile.aws" in result["url"] and not result["isLoading"]:
                    return "OTP"
                if result["isLoading"]:
                    return "LOADING"
                return "UNKNOWN"

            async def wait_for_state(target_states, timeout=60):
                deadline = time.time() + timeout
                while time.time() < deadline:
                    st = await detect_state()
                    if st in target_states or st == "DONE":
                        return st
                    if st == "CALLBACK":
                        return st
                    await asyncio.sleep(1.5)
                return await detect_state()
# === PLACEHOLDER_PHASE3B ===

            # ─── Phase 3: 注册表单 ─────────────────────────────────────
            log("阶段 3: 填写注册表单")
            await asyncio.sleep(2)
            await _dismiss_cookie(page)

            state = await wait_for_state(["NAME", "OTP", "PASSWORD", "CONSENT", "DONE"], timeout=30)
            log(f"当前状态: {state}, URL: {page.url[:80]}")

            # NAME
            if state == "NAME":
                name_field = page.locator('xpath=//input[contains(@placeholder,"Silva")]')
                if await name_field.count() == 0:
                    name_field = page.locator('xpath=//input[starts-with(@id,"formField")]')
                if await name_field.count() > 0:
                    await name_field.first.fill(full_name)
                    log(f"姓名已填入: {full_name}", "ok")
                    await asyncio.sleep(0.5)
                    await _js_click_submit()
                    await asyncio.sleep(4)
                state = await detect_state()

            # OTP
            if state not in ["DONE", "PASSWORD", "CONSENT", "CALLBACK"]:
                state = await wait_for_state(["OTP", "PASSWORD", "CONSENT", "DONE"], timeout=30)

            if state == "OTP":
                log("阶段 4: OTP 验证")
                await asyncio.sleep(3)
                otp_code = mail.wait_otp(timeout=90, poll_interval=3)
                if not otp_code:
                    log("OTP 等待超时!", "err")
                    await browser.close()
                    _cleanup()
                    return _partial_result("OTP超时")
                log(f"获取到验证码: {otp_code}", "ok")
                otp_input = None
                for sel in [
                    'xpath=//input[@inputmode="numeric"]',
                    'xpath=//input[@autocomplete="one-time-code"]',
                    'xpath=//input[contains(@name,"code")]',
                    'xpath=//input[contains(@placeholder,"digit")]',
                ]:
                    loc = page.locator(sel)
                    if await loc.count() > 0 and await loc.first.is_visible():
                        otp_input = loc.first
                        break
                if not otp_input:
                    all_inp = page.locator('xpath=//input[not(@type="hidden") and not(@type="password") and not(@type="email")]')
                    for i in range(await all_inp.count()):
                        inp = all_inp.nth(i)
                        if await inp.is_visible():
                            otp_input = inp
                            break
                if otp_input:
                    await otp_input.fill(otp_code)
                    await asyncio.sleep(0.5)
                    await _js_click_submit()
                    await asyncio.sleep(5)
                state = await detect_state()

            # PASSWORD
            if state not in ["DONE", "CONSENT", "CALLBACK"]:
                state = await wait_for_state(["PASSWORD", "CONSENT", "DONE"], timeout=30)

            if state == "PASSWORD":
                log("阶段 5: 设置密码")
                await asyncio.sleep(1)
                for _wait in range(10):
                    count = await page.locator('xpath=//input[@type="password"]').count()
                    if count >= 2:
                        break
                    await asyncio.sleep(1)
                await page.evaluate("""(pwd) => {
                    const inputs = Array.from(document.querySelectorAll('input[type="password"]'))
                        .filter(el => el.offsetWidth > 0);
                    function setVal(el, val) {
                        const ns = Object.getOwnPropertyDescriptor(
                            window.HTMLInputElement.prototype, 'value').set;
                        ns.call(el, val);
                        el.dispatchEvent(new Event('input', {bubbles: true}));
                        el.dispatchEvent(new Event('change', {bubbles: true}));
                    }
                    inputs.forEach(el => setVal(el, pwd));
                }""", password)
                log("密码已填入", "ok")
                await asyncio.sleep(0.5)
                await _js_click_submit()
                await asyncio.sleep(5)
                state = await detect_state()
# === PLACEHOLDER_PHASE6 ===

            # CONSENT
            if state not in ["DONE", "CALLBACK"]:
                state = await wait_for_state(["CONSENT", "DONE", "CALLBACK"], timeout=45)

            if state == "CONSENT" and not authorization_code:
                log("阶段 6: 授权同意页")
                await asyncio.sleep(3)
                for attempt in range(10):
                    try:
                        await page.evaluate("""() => {
                            const buttons = Array.from(document.querySelectorAll('button'));
                            const visible = buttons.filter(b => b.offsetWidth > 0 && b.offsetHeight > 0);
                            for (const b of visible) {
                                const t = (b.innerText || '').toLowerCase();
                                if (t.includes('allow') || t.includes('authorize') || t.includes('accept') || t.includes('confirm')) {
                                    b.click(); return;
                                }
                            }
                            if (visible.length > 0) visible[visible.length - 1].click();
                        }""")
                    except Exception:
                        break
                    await asyncio.sleep(3)
                    if authorization_code:
                        break
                    new_state = await detect_state()
                    if new_state != "CONSENT":
                        break

            # 等待回调 code
            if not authorization_code:
                log("等待 OAuth 回调...")
                for i in range(30):
                    if cancel_check and cancel_check():
                        log("用户取消", "err")
                        await browser.close()
                        _cleanup()
                        return _partial_result("用户取消")
                    if authorization_code:
                        break
                    current_url = page.url
                    if "127.0.0.1:3128" in current_url or "localhost:3128" in current_url:
                        qs = parse_qs(urlparse(current_url).query)
                        code = qs.get("code", [""])[0]
                        if code:
                            authorization_code = code
                            break
                    if "code=" in current_url and "code_challenge" not in current_url:
                        qs = parse_qs(urlparse(current_url).query)
                        code_val = qs.get("code", [""])[0]
                        if code_val and len(code_val) > 10:
                            authorization_code = code_val
                            break
                    if "awsapps.com" in current_url:
                        try:
                            await page.evaluate("""() => {
                                const buttons = Array.from(document.querySelectorAll('button'));
                                const visible = buttons.filter(b => b.offsetWidth > 0 && b.offsetHeight > 0);
                                for (const b of visible) {
                                    const t = (b.innerText || '').toLowerCase();
                                    if (t.includes('allow') || t.includes('authorize') || t.includes('accept') || t.includes('confirm')) {
                                        b.click(); return;
                                    }
                                }
                                if (visible.length > 0) visible[visible.length - 1].click();
                            }""")
                        except Exception:
                            pass
                    await asyncio.sleep(2)

            await browser.close()
    finally:
        _cleanup()

    # ─── Phase 7: Token 交换 ──────────────────────────────────────────
    if not authorization_code:
        log("未获取到授权码!", "err")
        return _partial_result("未获取授权码")

    log("已获取授权码", "ok")
    log("正在交换 Token...")

    token_resp = None
    for _token_retry in range(3):
        try:
            token_resp = s.post(f"{REG_OIDC}/token", json={
                "clientId": client_id, "clientSecret": client_secret,
                "grantType": "authorization_code",
                "code": authorization_code,
                "redirectUri": REG_REDIRECT_URI,
                "codeVerifier": code_verifier,
            }, timeout=30, verify=False)
            break
        except Exception:
            if _token_retry < 2:
                time.sleep(3)
            else:
                log("Token 交换连接失败", "err")
                return _partial_result("Token交换连接失败")

    if token_resp.status_code != 200:
        log(f"Token 交换失败: HTTP {token_resp.status_code}", "err")
        return _partial_result("Token交换失败")

    tokens = token_resp.json()
    access_token = tokens.get("accessToken", "")
    refresh_token = tokens.get("refreshToken", "")
    expires_in = tokens.get("expiresIn", 28800)

    if not access_token:
        log("Token 交换未返回 accessToken", "err")
        return _partial_result("无accessToken")

    log("Token 获取成功", "ok")

    if auto_login:
        persist_tokens(client_id, client_secret, access_token, refresh_token, expires_in, log, email=email)
        inject_machine_ids(log)
        if skip_onboard:
            skip_onboarding(log)

    log("=" * 40, "ok")
    log("注册完成! (RoxyBrowser)", "ok")
    log(f"  Email: {email}", "ok")
    log(f"  Password: {password}", "ok")
    log("=" * 40, "ok")

    return {
        "email": email, "password": password, "full_name": full_name,
        "provider": "BuilderId", "authMethod": "IdC", "region": "us-east-1",
        "clientId": client_id, "clientSecret": client_secret,
        "clientIdHash": _sha1_hash(client_id),
        "accessToken": access_token, "refreshToken": refresh_token,
        "expiresAt": (datetime.now(timezone.utc) + timedelta(seconds=expires_in)).strftime("%Y/%m/%d %H:%M:%S"),
        "browser": "RoxyBrowser",
    }
