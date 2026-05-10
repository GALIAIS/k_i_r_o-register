"""
Kiro 自动注册模块 - Playwright + HTTP 混合方案
浏览器走完 signin.aws -> profile.aws 的完整重定向链
注册完成后自动注入 token 实现 Kiro 免登录

依赖: curl_cffi, playwright, playwright-stealth, cryptography
"""
import asyncio
import base64
import hashlib
import json
import os
import re
import secrets
import socket
import stat
import string
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse


# ─── 常量 ─────────────────────────────────────────────────────────────────────

SHIROMAIL_BASE = ""
SHIROMAIL_KEY = ""
SHIROMAIL_DOMAIN_ID = 0

REG_OIDC = "https://oidc.us-east-1.amazonaws.com"
REG_SCOPES = [
    "codewhisperer:completions", "codewhisperer:analysis",
    "codewhisperer:conversations", "codewhisperer:transformations",
    "codewhisperer:taskassist",
]
REG_REDIRECT_URI = "http://127.0.0.1:3128"
KIRO_SIGNIN_URL = "https://app.kiro.dev/signin"
ISSUER_URL = "https://view.awsapps.com/start/"
REG_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

JWE_ALG = "RSA-OAEP-256"
JWE_ENC = "A256GCM"
JWE_CTY = "application/aws+signin+jwe"

_FIRST_NAMES = [
    "James", "Robert", "Michael", "William", "David", "Richard", "Joseph", "Thomas",
    "Christopher", "Daniel", "Matthew", "Anthony", "Mark", "Steven", "Andrew", "Paul",
    "Oliver", "Henry", "Samuel", "Benjamin", "Alexander", "Sebastian", "Elijah", "Owen",
    "Mary", "Patricia", "Jennifer", "Linda", "Elizabeth", "Susan", "Jessica", "Sarah",
]
_LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis",
    "Rodriguez", "Martinez", "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson",
    "Lee", "Thompson", "White", "Harris", "Clark", "Lewis", "Robinson", "Walker",
]


# ─── 指纹随机化 ──────────────────────────────────────────────────────────────

_SCREEN_RESOLUTIONS = [
    (1920, 1080), (2560, 1440), (1366, 768), (1536, 864),
    (1440, 900), (1680, 1050), (1600, 900), (1280, 720),
    (1920, 1200), (2560, 1080), (3440, 1440), (1280, 1024),
]

_VIEWPORT_SIZES = [
    (1280, 800), (1366, 768), (1440, 900), (1536, 864),
    (1600, 900), (1680, 1050), (1920, 1080), (1280, 720),
]

_LOCALES = ["en-US", "en-GB", "en-CA", "en-AU"]

_TIMEZONES = [
    "America/New_York", "America/Chicago", "America/Denver",
    "America/Los_Angeles", "America/Toronto", "Europe/London",
]

_WEBGL_VENDORS = ["Google Inc. (NVIDIA)", "Google Inc. (AMD)", "Google Inc. (Intel)"]
_WEBGL_RENDERERS = [
    "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)",
    "ANGLE (NVIDIA, NVIDIA GeForce RTX 4070 Direct3D11 vs_5_0 ps_5_0, D3D11)",
    "ANGLE (AMD, AMD Radeon RX 6700 XT Direct3D11 vs_5_0 ps_5_0, D3D11)",
    "ANGLE (Intel, Intel(R) UHD Graphics 770 Direct3D11 vs_5_0 ps_5_0, D3D11)",
    "ANGLE (NVIDIA, NVIDIA GeForce GTX 1660 SUPER Direct3D11 vs_5_0 ps_5_0, D3D11)",
    "ANGLE (AMD, AMD Radeon RX 580 Direct3D11 vs_5_0 ps_5_0, D3D11)",
]

_CHROME_VERSIONS = [
    "131.0.6778.86", "131.0.6778.109", "132.0.6834.57", "132.0.6834.83",
    "133.0.6876.0", "130.0.6723.117", "131.0.6778.140",
]

_PLATFORM_VERSIONS = [
    "10.0.0", "10.0.1", "15.0.0", "14.6.1",
]


def _random_machine_ids():
    """生成一组随机但格式正确的机器标识"""
    import uuid
    service_id = str(uuid.uuid4())
    mac_machine_id = secrets.token_hex(64)  # 128 chars hex (SHA-512 format)
    machine_id = secrets.token_hex(32)  # 64 chars hex (SHA-256 format)
    sqm_id = "{" + str(uuid.uuid4()).upper() + "}"
    return {
        "storage.serviceMachineId": service_id,
        "telemetry.devDeviceId": service_id,
        "telemetry.macMachineId": mac_machine_id,
        "telemetry.machineId": machine_id,
        "telemetry.sqmId": sqm_id,
    }


def _random_ua():
    """生成随机 Chrome UA"""
    ver = secrets.choice(_CHROME_VERSIONS)
    return (f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            f"(KHTML, like Gecko) Chrome/{ver} Safari/537.36")


def _random_fingerprint_config():
    """生成完整的随机浏览器指纹配置"""
    screen = secrets.choice(_SCREEN_RESOLUTIONS)
    viewport = secrets.choice(_VIEWPORT_SIZES)
    while viewport[0] > screen[0] or viewport[1] > screen[1]:
        viewport = secrets.choice(_VIEWPORT_SIZES)
    return {
        "viewport": {"width": viewport[0], "height": viewport[1]},
        "screen": {"width": screen[0], "height": screen[1]},
        "locale": secrets.choice(_LOCALES),
        "timezone": secrets.choice(_TIMEZONES),
        "user_agent": _random_ua(),
        "webgl_vendor": secrets.choice(_WEBGL_VENDORS),
        "webgl_renderer": secrets.choice(_WEBGL_RENDERERS),
        "hardware_concurrency": secrets.choice([4, 6, 8, 12, 16]),
        "device_memory": secrets.choice([4, 8, 16, 32]),
        "color_depth": 24,
        "pixel_ratio": secrets.choice([1.0, 1.25, 1.5, 2.0]),
        "max_touch_points": 0,
        "platform": "Win32",
        "canvas_noise": secrets.token_hex(4),
    }


def _build_fingerprint_script(fp_config):
    """生成注入浏览器的指纹覆盖 JS"""
    return """() => {
        const config = """ + json.dumps(fp_config) + """;

        // Navigator overrides
        Object.defineProperty(navigator, 'hardwareConcurrency', {get: () => config.hardware_concurrency});
        Object.defineProperty(navigator, 'deviceMemory', {get: () => config.device_memory});
        Object.defineProperty(navigator, 'maxTouchPoints', {get: () => config.max_touch_points});
        Object.defineProperty(navigator, 'platform', {get: () => config.platform});
        Object.defineProperty(navigator, 'languages', {get: () => [config.locale, config.locale.split('-')[0]]});

        // Screen overrides
        Object.defineProperty(screen, 'width', {get: () => config.screen.width});
        Object.defineProperty(screen, 'height', {get: () => config.screen.height});
        Object.defineProperty(screen, 'availWidth', {get: () => config.screen.width});
        Object.defineProperty(screen, 'availHeight', {get: () => config.screen.height - 40});
        Object.defineProperty(screen, 'colorDepth', {get: () => config.color_depth});
        Object.defineProperty(screen, 'pixelDepth', {get: () => config.color_depth});
        Object.defineProperty(window, 'devicePixelRatio', {get: () => config.pixel_ratio});

        // WebGL fingerprint
        const getParameterOrig = WebGLRenderingContext.prototype.getParameter;
        WebGLRenderingContext.prototype.getParameter = function(param) {
            if (param === 37445) return config.webgl_vendor;
            if (param === 37446) return config.webgl_renderer;
            return getParameterOrig.call(this, param);
        };
        const getParameterOrig2 = WebGL2RenderingContext.prototype.getParameter;
        WebGL2RenderingContext.prototype.getParameter = function(param) {
            if (param === 37445) return config.webgl_vendor;
            if (param === 37446) return config.webgl_renderer;
            return getParameterOrig2.call(this, param);
        };

        // Canvas fingerprint noise
        const toDataURLOrig = HTMLCanvasElement.prototype.toDataURL;
        HTMLCanvasElement.prototype.toDataURL = function(type) {
            const ctx = this.getContext('2d');
            if (ctx) {
                const noise = parseInt(config.canvas_noise, 16);
                const imageData = ctx.getImageData(0, 0, Math.min(this.width, 2), Math.min(this.height, 2));
                for (let i = 0; i < imageData.data.length; i += 4) {
                    imageData.data[i] = (imageData.data[i] + (noise >> (i % 8)) % 3) & 0xFF;
                }
                ctx.putImageData(imageData, 0, 0);
            }
            return toDataURLOrig.call(this, type);
        };

        // AudioContext fingerprint
        const origGetChannelData = AudioBuffer.prototype.getChannelData;
        AudioBuffer.prototype.getChannelData = function(channel) {
            const data = origGetChannelData.call(this, channel);
            if (data.length > 0) {
                const noise = parseInt(config.canvas_noise.slice(0, 4), 16) / 65536;
                for (let i = 0; i < Math.min(data.length, 10); i++) {
                    data[i] += (noise * 0.0000001);
                }
            }
            return data;
        };

        // ClientRects noise
        const origGetBoundingClientRect = Element.prototype.getBoundingClientRect;
        Element.prototype.getBoundingClientRect = function() {
            const rect = origGetBoundingClientRect.call(this);
            const noise = parseInt(config.canvas_noise.slice(4, 8), 16) % 3 * 0.00001;
            return new DOMRect(rect.x + noise, rect.y + noise, rect.width + noise, rect.height + noise);
        };

        // Permissions API
        const origQuery = navigator.permissions.query;
        navigator.permissions.query = function(desc) {
            if (desc.name === 'notifications') {
                return Promise.resolve({state: 'prompt', onchange: null});
            }
            return origQuery.call(this, desc);
        };

        // Connection API
        if (navigator.connection) {
            Object.defineProperty(navigator.connection, 'rtt', {get: () => [50, 100, 150][Math.floor(Math.random() * 3)]});
            Object.defineProperty(navigator.connection, 'downlink', {get: () => [1.5, 2.5, 5, 10][Math.floor(Math.random() * 4)]});
        }

        // Battery API - 返回真实感的电池状态
        if (!navigator.getBattery) {
            navigator.getBattery = () => Promise.resolve({
                charging: Math.random() > 0.3,
                chargingTime: Math.random() > 0.5 ? Infinity : Math.floor(Math.random() * 7200),
                dischargingTime: Math.floor(Math.random() * 20000) + 3600,
                level: 0.3 + Math.random() * 0.65,
                addEventListener: () => {},
            });
        }

        // Performance.now() 微小噪声，防止精确计时检测
        const perfNowOrig = Performance.prototype.now;
        Performance.prototype.now = function() {
            return perfNowOrig.call(this) + Math.random() * 0.1;
        };

        // Date.now() 微小偏移
        const dateNowOrig = Date.now;
        Date.now = function() {
            return dateNowOrig() + Math.floor(Math.random() * 2);
        };

        // 隐藏 webdriver 标志
        Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
        delete navigator.__proto__.webdriver;

        // Chrome runtime 模拟
        if (!window.chrome) {
            window.chrome = {runtime: {}, loadTimes: () => ({}), csi: () => ({})};
        }

        // Plugin 模拟
        Object.defineProperty(navigator, 'plugins', {
            get: () => {
                const arr = [
                    {name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer', description: 'Portable Document Format'},
                    {name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', description: ''},
                    {name: 'Native Client', filename: 'internal-nacl-plugin', description: ''},
                ];
                arr.item = (i) => arr[i];
                arr.namedItem = (n) => arr.find(p => p.name === n);
                arr.refresh = () => {};
                return arr;
            }
        });

        // MimeTypes 模拟
        Object.defineProperty(navigator, 'mimeTypes', {
            get: () => {
                const arr = [
                    {type: 'application/pdf', suffixes: 'pdf', description: 'Portable Document Format'},
                    {type: 'application/x-google-chrome-pdf', suffixes: 'pdf', description: 'Portable Document Format'},
                ];
                arr.item = (i) => arr[i];
                arr.namedItem = (n) => arr.find(m => m.type === n);
                return arr;
            }
        });
    }"""


def inject_machine_ids(log=print):
    """注入随机机器码到 Kiro storage.json"""
    storage_path = Path(os.environ.get("APPDATA", "")) / "Kiro" / "User" / "globalStorage" / "storage.json"
    if not storage_path.exists():
        log("storage.json 不存在，跳过机器码注入", "warn")
        return None

    ids = _random_machine_ids()
    try:
        storage = json.loads(storage_path.read_text(encoding="utf-8"))
        for key, value in ids.items():
            storage[key] = value
        storage_path.write_text(json.dumps(storage, indent=4), encoding="utf-8")
        log(f"机器码已注入: machineId={ids['telemetry.machineId'][:16]}...", "ok")
        return ids
    except Exception as e:
        log(f"机器码注入失败: {e}", "error")
        return None


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _sha1_hash(value: str) -> str:
    return hashlib.sha1(value.encode()).hexdigest()


import random as _random

async def _human_type(page, locator, text, min_delay=35, max_delay=120):
    """模拟人类打字：逐字输入，随机延迟，偶尔停顿"""
    await locator.click()
    await asyncio.sleep(_random.uniform(0.2, 0.5))
    await locator.fill("")
    for i, ch in enumerate(text):
        await page.keyboard.type(ch, delay=0)
        delay = _random.uniform(min_delay, max_delay) / 1000
        # 每隔几个字符偶尔有较长停顿（模拟思考/看键盘）
        if i > 0 and _random.random() < 0.08:
            delay += _random.uniform(0.2, 0.6)
        await asyncio.sleep(delay)
    await asyncio.sleep(_random.uniform(0.3, 0.8))


async def _human_delay(min_s=1.0, max_s=3.0):
    """随机等待，模拟人类反应时间"""
    await asyncio.sleep(_random.uniform(min_s, max_s))


async def _move_to_element(page, locator):
    """模拟鼠标移动到元素位置"""
    try:
        box = await locator.bounding_box()
        if box:
            target_x = box["x"] + box["width"] * _random.uniform(0.3, 0.7)
            target_y = box["y"] + box["height"] * _random.uniform(0.3, 0.7)
            await page.mouse.move(target_x, target_y, steps=_random.randint(5, 15))
            await asyncio.sleep(_random.uniform(0.1, 0.3))
    except Exception:
        pass


def _generate_password(length=16):
    upper = string.ascii_uppercase
    lower = string.ascii_lowercase
    digits = string.digits
    special = "!@#$%&*"
    required = [
        secrets.choice(upper), secrets.choice(upper),
        secrets.choice(lower), secrets.choice(lower),
        secrets.choice(digits), secrets.choice(digits),
        secrets.choice(special), secrets.choice(special),
    ]
    pool = upper + lower + digits + special
    rest = [secrets.choice(pool) for _ in range(length - len(required))]
    chars = required + rest
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars)


def _generate_name():
    return f"{secrets.choice(_FIRST_NAMES)} {secrets.choice(_LAST_NAMES)}"


class ShiroMailClient:
    """兼容层 - 委托给 mail_provider 模块"""
    def __init__(self, base_url=None, api_key=None, domain_id=None):
        from mail_providers import ShiroMailProvider
        self._provider = ShiroMailProvider(
            base_url=base_url or SHIROMAIL_BASE,
            api_key=api_key or SHIROMAIL_KEY,
            domain_id=domain_id or SHIROMAIL_DOMAIN_ID,
        )

    def create_mailbox(self) -> str:
        addr = self._provider.create_mailbox()
        self.address = self._provider.address
        return addr

    def wait_otp(self, timeout=120, poll_interval=3) -> str:
        return self._provider.wait_otp(timeout=timeout, poll_interval=poll_interval)


def persist_tokens(client_id, client_secret, access_token, refresh_token, expires_in, log=print, email=None):
    cache_dir = Path.home() / ".aws" / "sso" / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    client_id_hash = _sha1_hash(client_id)
    expires_at_str = (datetime.now(timezone.utc) + timedelta(seconds=expires_in)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    token_data = {
        "accessToken": access_token,
        "refreshToken": refresh_token,
        "expiresAt": expires_at_str,
        "clientIdHash": client_id_hash,
        "clientId": client_id,
        "authMethod": "IdC",
        "provider": "BuilderId",
        "region": "us-east-1",
    }
    if email:
        token_data["email"] = email
    token_path = cache_dir / "kiro-auth-token.json"
    token_path.write_text(json.dumps(token_data, indent=2), encoding="utf-8")
    try:
        os.chmod(token_path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    log("Token 已写入本地", "ok")
    client_data = {
        "clientId": client_id,
        "clientSecret": client_secret,
        "expiresAt": (datetime.now(timezone.utc) + timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
    }
    client_path = cache_dir / f"{client_id_hash}.json"
    client_path.write_text(json.dumps(client_data, indent=2), encoding="utf-8")
    try:
        os.chmod(client_path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    log("客户端信息已保存", "ok")


def skip_onboarding(log=print):
    storage_path = Path(os.environ.get("APPDATA", "")) / "Kiro" / "User" / "globalStorage" / "storage.json"
    if not storage_path.exists():
        return False
    try:
        storage = json.loads(storage_path.read_text(encoding="utf-8"))
        storage["kiroAgent.onboarding.onboardingCompleted"] = "true"
        storage_path.write_text(json.dumps(storage, indent=2), encoding="utf-8")
        log("已跳过引导页", "ok")
        return True
    except Exception as e:
        log(f"跳过引导页失败: {e}", "err")
        return False


async def _dismiss_cookie(page):
    for sel in [
        'xpath=//button[@data-id="awsccc-cb-btn-accept"]',
        'xpath=//div[contains(@class,"awsccc")]//button[contains(text(),"Accept")]',
        'xpath=//button[text()="Accept"]',
    ]:
        loc = page.locator(sel)
        try:
            if await loc.count() > 0 and await loc.first.is_visible():
                await loc.first.click()
                await asyncio.sleep(1)
                return True
        except Exception:
            pass
    try:
        await page.evaluate("""() => {
            const el = document.querySelector('[id*="awsccc"], [class*="awsccc"]');
            if (el) el.remove();
        }""")
    except Exception:
        pass
    return False


async def _click_submit(page, label_contains=None, timeout=10000):
    if label_contains:
        btn = page.locator(f'xpath=//form//button[@type="submit"][contains(text(),"{label_contains}")]')
    else:
        btn = page.locator('xpath=//form//button[@type="submit"]')
    for i in range(await btn.count()):
        b = btn.nth(i)
        if await b.is_visible():
            await b.scroll_into_view_if_needed()
            await asyncio.sleep(0.3)
            await b.click(timeout=timeout)
            return True
    return False


async def register(headless=True, auto_login=True, skip_onboard=True,
                   mail_url=None, mail_key=None, mail_domain_id=None,
                   mail_provider_instance=None,
                   log=print, cancel_check=None):
    """
    完整的 Kiro 自动注册流程。

    Args:
        headless: 是否无头模式
        auto_login: 是否注入本地 token
        skip_onboard: 是否跳过 onboarding
        mail_url: API 地址
        mail_key: API Key (ShiroMail 需要)
        mail_domain_id: Domain ID (ShiroMail 需要)
        mail_provider_instance: 已创建的 MailProvider 实例 (优先使用)
        log: 日志回调 log(msg, level)
        cancel_check: 取消检查回调，返回 True 表示取消
    Returns:
        dict with account info or None
    """
    from curl_cffi import requests as curl_requests
    from playwright.async_api import async_playwright
    from playwright_stealth import Stealth

    if cancel_check and cancel_check():
        return None

    # 生成随机指纹配置
    fp_config = _random_fingerprint_config()
    log(f"浏览器指纹: Chrome/{fp_config['user_agent'].split('Chrome/')[1].split(' ')[0]}, "
        f"{fp_config['viewport']['width']}x{fp_config['viewport']['height']}, "
        f"{fp_config['timezone']}", "dbg")

    s = curl_requests.Session(impersonate="chrome131")
    if mail_provider_instance:
        mail = mail_provider_instance
    else:
        mail = ShiroMailClient(base_url=mail_url, api_key=mail_key, domain_id=mail_domain_id)
    email = mail.create_mailbox()
    password = _generate_password()
    full_name = _generate_name()
    log(f"邮箱: {email}", "ok")
    log(f"密码: {password[:4]}****")
    log(f"姓名: {full_name}")

    def _partial_result(reason="unknown"):
        """注册未完成时返回部分信息，让调用方仍可入库"""
        return {
            "email": email,
            "password": password,
            "full_name": full_name,
            "provider": "BuilderId",
            "authMethod": "IdC",
            "region": "us-east-1",
            "accessToken": "",
            "refreshToken": "",
            "incomplete": True,
            "failReason": reason,
        }

    # Phase 1: OIDC 客户端注册
    log("阶段 1: OIDC 客户端注册")
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = _b64url(hashlib.sha256(code_verifier.encode()).digest())
    state_val = secrets.token_urlsafe(32)

    reg_resp = s.post(f"{REG_OIDC}/client/register", json={
        "clientName": "Kiro IDE", "clientType": "public",
        "grantTypes": ["authorization_code", "refresh_token"],
        "issuerUrl": ISSUER_URL,
        "redirectUris": [REG_REDIRECT_URI], "scopes": REG_SCOPES,
    }, timeout=25, verify=False)
    reg = reg_resp.json()
    if "clientId" not in reg:
        log(f"OIDC 注册失败: {reg}", "err")
        return _partial_result("OIDC注册失败")
    client_id = reg["clientId"]
    client_secret = reg["clientSecret"]
    log("OIDC 客户端注册成功", "ok")

    signin_url = f"{KIRO_SIGNIN_URL}?" + urlencode({
        "state": state_val,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "redirect_uri": REG_REDIRECT_URI,
        "redirect_from": "KiroIDE",
    })

    # Phase 2: 本地回调服务器 + Playwright
    log(f"阶段 2: 启动浏览器 (headless={headless})")
    authorization_code = ""

    class CallbackHandler(BaseHTTPRequestHandler):
        signin_callback_params = {}

        def do_GET(self_h):
            nonlocal authorization_code
            parsed = urlparse(self_h.path)
            qs = parse_qs(parsed.query)
            code = qs.get("code", [""])[0]
            if code:
                authorization_code = code
                log("已收到授权回调", "ok")
                self_h.send_response(200)
                self_h.send_header("Content-Type", "text/html")
                self_h.end_headers()
                self_h.wfile.write(b"<html><body><h2>Registration complete!</h2></body></html>")
            elif "signin/callback" in parsed.path or qs.get("login_option"):
                CallbackHandler.signin_callback_params = {k: v[0] for k, v in qs.items()}
                log("收到登录回调", "ok")
                self_h.send_response(200)
                self_h.send_header("Content-Type", "text/html")
                self_h.end_headers()
                self_h.wfile.write(b"<html><body><p>Redirecting...</p></body></html>")
            else:
                self_h.send_response(200)
                self_h.send_header("Content-Type", "text/html")
                self_h.end_headers()
                self_h.wfile.write(b"<html><body><p>OK</p></body></html>")

        def log_message(self_h, *args):
            pass

    # 确保端口可用
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("127.0.0.1", 3128))
        sock.close()
    except OSError:
        sock.close()
        try:
            import subprocess
            r = subprocess.run(["netstat", "-ano"], capture_output=True, text=True)
            for line in r.stdout.splitlines():
                if ":3128" in line and "LISTENING" in line:
                    pid = line.strip().split()[-1]
                    if pid.isdigit() and int(pid) != os.getpid():
                        subprocess.run(["taskkill", "/F", "/PID", pid], capture_output=True)
            await asyncio.sleep(1)
        except Exception:
            pass

    callback_server = HTTPServer(("127.0.0.1", 3128), CallbackHandler)
    callback_server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv_thread = threading.Thread(target=callback_server.serve_forever, daemon=True)
    srv_thread.start()
    log("本地回调服务器已启动 (127.0.0.1:3128)", "ok")

    try:
        async with async_playwright() as p:
            launch_args = [
                "--disable-blink-features=AutomationControlled",
                "--disable-features=IsolateOrigins,site-per-process",
                "--no-first-run",
                f"--window-size={fp_config['screen']['width']},{fp_config['screen']['height']}",
                "--disable-background-timer-throttling",
                "--disable-backgrounding-occluded-windows",
                "--disable-renderer-backgrounding",
            ]
            if headless:
                launch_args += ["--disable-gpu", "--no-sandbox",
                                "--disable-setuid-sandbox", "--disable-dev-shm-usage"]
            browser = await p.chromium.launch(headless=headless, args=launch_args)
            context = await browser.new_context(
                viewport=fp_config["viewport"],
                screen=fp_config["screen"],
                locale=fp_config["locale"],
                timezone_id=fp_config["timezone"],
                user_agent=fp_config["user_agent"],
                color_scheme="light",
                device_scale_factor=fp_config["pixel_ratio"],
            )
            page = await context.new_page()
            await Stealth().apply_stealth_async(page)

            # 拦截 profile.aws API 响应用于调试
            async def _on_profile_response(response):
                url = response.url
                if "profile.aws" in url and "/api/" in url:
                    try:
                        body = await response.text()
                        endpoint = url.split("/api/")[-1]
                        log(f"[API] {endpoint} → {response.status} {body[:150]}", "dbg")
                    except Exception:
                        pass
            page.on("response", _on_profile_response)

            # 注入深度指纹覆盖
            await context.add_init_script(_build_fingerprint_script(fp_config))

            await page.goto(signin_url, timeout=60000)
            await page.wait_for_load_state("networkidle", timeout=30000)
            await asyncio.sleep(3)
            await _dismiss_cookie(page)

            # 点击 AWS Builder ID 按钮
            if "app.kiro.dev" in page.url:
                log("正在选择登录方式...")
                await asyncio.sleep(2)
                signin_clicked = False
                for sel in [
                    'xpath=//*[@id="layout-viewport"]/div/div/div/div[2]/div/div[1]/button[3]',
                    'xpath=//button[contains(text(),"AWS Builder ID")]',
                    'xpath=//button[contains(text(),"Builder ID")]',
                    'xpath=//button[contains(text(),"Sign in")]',
                    'xpath=//button[contains(text(),"Continue")]',
                ]:
                    loc = page.locator(sel)
                    try:
                        if await loc.count() > 0 and await loc.first.is_visible():
                            await loc.first.click()
                            signin_clicked = True
                            log("已点击登录按钮", "ok")
                            break
                    except Exception:
                        pass

                if signin_clicked:
                    await asyncio.sleep(3)
                    if not CallbackHandler.signin_callback_params:
                        try:
                            await page.evaluate("""() => {
                                const btn = document.querySelector('#layout-viewport button:nth-child(3)') ||
                                            document.querySelectorAll('#layout-viewport button')[2];
                                if (btn) btn.dispatchEvent(new MouseEvent('click', {bubbles: true, cancelable: true}));
                            }""")
                        except Exception:
                            pass
                        await asyncio.sleep(3)

                for _ in range(20):
                    if CallbackHandler.signin_callback_params:
                        break
                    await asyncio.sleep(1)

            # 构造 OIDC authorize URL
            if CallbackHandler.signin_callback_params and not authorization_code:
                log("正在跳转到授权页面...")
                authorize_url = f"{REG_OIDC}/authorize?" + urlencode({
                    "response_type": "code",
                    "client_id": client_id,
                    "redirect_uri": REG_REDIRECT_URI,
                    "scopes": ",".join(REG_SCOPES),
                    "state": state_val,
                    "code_challenge": code_challenge,
                    "code_challenge_method": "S256",
                })
                await page.goto(authorize_url, timeout=60000)
                await page.wait_for_load_state("networkidle", timeout=30000)
                await asyncio.sleep(3)

            # 等待到达 signin.aws 或 profile.aws
            for _ in range(10):
                if "signin.aws" in page.url or "profile.aws" in page.url:
                    break
                await asyncio.sleep(2)
            await asyncio.sleep(2)
            log("已到达注册页面", "ok")

            # 如果在 signin.aws，输入邮箱
            if "signin.aws" in page.url:
                email_input = page.locator('xpath=//input[@type="email"]')
                if await email_input.count() == 0:
                    email_input = page.locator('xpath=//input[@type="text"]').first
                await _move_to_element(page, email_input)
                await _human_type(page, email_input, email)
                await _human_delay(0.8, 1.5)
                log(f"邮箱已填入: {email}")
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
                await _human_delay(2, 4)

            # 等待 profile.aws
            for _ in range(15):
                if "profile.aws" in page.url:
                    break
                await asyncio.sleep(2)
            await asyncio.sleep(2)

            if "profile.aws" not in page.url:
                log(f"未能到达注册页面 (当前: {page.url})", "err")
                await browser.close()
                callback_server.shutdown()
                return _partial_result("未到达注册页面")

            # 预热行为：模拟真实用户浏览页面，让 TES 收集正常行为数据
            try:
                vp = page.viewport_size
                for _ in range(3):
                    await page.mouse.move(
                        _random.randint(100, vp["width"] - 100),
                        _random.randint(100, vp["height"] - 100),
                        steps=_random.randint(10, 25)
                    )
                    await asyncio.sleep(_random.uniform(0.3, 0.8))
                await page.mouse.wheel(0, _random.randint(50, 150))
                await asyncio.sleep(_random.uniform(0.5, 1.0))
                await page.mouse.wheel(0, -_random.randint(30, 80))
                await asyncio.sleep(_random.uniform(0.3, 0.6))
            except Exception:
                pass

            # ─── 状态机 ───────────────────────────────────────────────────
            async def detect_state():
                if authorization_code:
                    return "DONE"
                url = page.url
                if "127.0.0.1:3128" in url or "localhost:3128" in url:
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
                        const urlHasOtp = url.includes('verify-otp') || url.includes('otp');
                        // 检测是否为授权同意页面（有 allow/authorize 按钮）
                        const buttons = Array.from(document.querySelectorAll('button'));
                        const visibleBtns = buttons.filter(b => b.offsetWidth > 0 && b.offsetHeight > 0);
                        const hasConsentBtn = visibleBtns.some(b => {
                            const t = (b.innerText || '').toLowerCase();
                            return t.includes('allow') || t.includes('authorize') ||
                                   t.includes('accept') || t.includes('confirm');
                        });
                        // 检测页面是否仍在加载（无可交互元素）
                        const hasAnyInput = document.querySelectorAll('input:not([type="hidden"])').length > 0;
                        const hasAnyButton = visibleBtns.length > 0;
                        const isLoading = !hasAnyInput && !hasAnyButton;
                        return {
                            url, visiblePwdCount: visiblePwds.length,
                            hasName: !!(nameInput && nameInput.offsetWidth > 0),
                            hasOtp: !!(otpInput && otpInput.offsetWidth > 0),
                            hasEmail: !!(emailInput && emailInput.offsetWidth > 0),
                            urlHasOtp, hasConsentBtn, isLoading,
                        };
                    }""")
                except Exception:
                    return "UNKNOWN"
                if "chrome-error" in result["url"]:
                    return "CALLBACK"
                if result["visiblePwdCount"] >= 1:
                    return "PASSWORD"
                if result["hasOtp"] or (result["urlHasOtp"] and not result["isLoading"]):
                    return "OTP"
                if result["hasName"]:
                    return "NAME"
                if result["hasEmail"]:
                    return "EMAIL"
                if "awsapps.com" in result["url"] and result["hasConsentBtn"]:
                    return "CONSENT"
                if "profile.aws" in result["url"]:
                    return "LOADING"
                if result["isLoading"]:
                    return "LOADING"
                return "UNKNOWN"

            async def wait_for_state(target_states, timeout=60):
                deadline = time.time() + timeout
                while time.time() < deadline:
                    if cancel_check and cancel_check():
                        return "CANCELLED"
                    st = await detect_state()
                    if st in target_states or st == "DONE":
                        return st
                    if st == "CALLBACK":
                        return st
                    await asyncio.sleep(1.5)
                return await detect_state()

            # Phase 3: 姓名填写
            log("阶段 3: 填写注册表单")
            await asyncio.sleep(2)
            await _dismiss_cookie(page)

            state = await wait_for_state(["NAME", "OTP", "PASSWORD", "CONSENT", "DONE"], timeout=30)
            if state == "CANCELLED":
                await browser.close()
                callback_server.shutdown()
                return _partial_result("用户取消")
            if state == "NAME":
                name_field = page.locator('xpath=//input[contains(@placeholder,"Silva")]')
                for attempt in range(3):
                    try:
                        await _move_to_element(page, name_field.first)
                        await _human_type(page, name_field.first, full_name)
                        await _human_delay(0.5, 1.0)
                        filled_val = await name_field.first.input_value()
                        if filled_val == full_name:
                            log(f"姓名已填入: '{full_name}'", "ok")
                            break
                    except Exception:
                        await asyncio.sleep(1)
                for attempt in range(3):
                    clicked = False
                    try:
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
                        clicked = True
                    except Exception:
                        pass
                    if not clicked:
                        try:
                            await page.keyboard.press("Enter")
                        except Exception:
                            pass
                    await asyncio.sleep(4)
                    new_state = await detect_state()
                    if new_state != "NAME":
                        log("姓名已提交", "ok")
                        break
                state = await detect_state()

            # Phase 4: OTP 验证
            if state not in ["DONE", "PASSWORD", "CONSENT", "CALLBACK"]:
                state = await wait_for_state(["OTP", "PASSWORD", "CONSENT", "DONE"], timeout=30)

            if state == "CANCELLED":
                await browser.close()
                callback_server.shutdown()
                return _partial_result("用户取消")
            if state == "OTP":
                log("阶段 4: OTP 验证")
                # 等待 profile.aws 页面 React 渲染完成
                await asyncio.sleep(3)
                otp_selectors = [
                    'xpath=//input[@inputmode="numeric"]',
                    'xpath=//input[@autocomplete="one-time-code"]',
                    'xpath=//input[contains(@placeholder,"6-digit") or contains(@placeholder,"digit")]',
                    'xpath=//input[contains(@name,"otp") or contains(@name,"code") or contains(@name,"verif")]',
                    'xpath=//input[contains(@id,"otp") or contains(@id,"code") or contains(@id,"verif")]',
                    'xpath=//input[contains(@placeholder,"code") or contains(@placeholder,"Code") or contains(@placeholder,"验证")]',
                    'xpath=//input[contains(@aria-label,"code") or contains(@aria-label,"verif")]',
                    'xpath=//input[contains(@class,"verification") or contains(@class,"otp")]',
                    'css=input[data-testid*="code"]',
                    'css=input[data-testid*="otp"]',
                    'css=input[data-testid*="verif"]',
                ]
                otp_input = None
                # 重试最多 3 次，每次等 2 秒（应对 React 渲染延迟）
                for retry in range(3):
                    for sel in otp_selectors:
                        loc = page.locator(sel)
                        if await loc.count() > 0 and await loc.first.is_visible():
                            otp_input = loc.first
                            break
                    if otp_input:
                        break
                    # fallback: 找页面上唯一可见的 text/tel/number 输入框
                    all_inp = page.locator('xpath=//input[not(@type="hidden") and not(@type="password") and not(@type="email")]')
                    for i in range(await all_inp.count()):
                        inp = all_inp.nth(i)
                        if await inp.is_visible():
                            inp_type = await inp.get_attribute("type") or "text"
                            if inp_type in ("text", "tel", "number", ""):
                                otp_input = inp
                                break
                    if otp_input:
                        break
                    if retry < 2:
                        log(f"OTP 输入框未就绪，等待重试 ({retry+1}/3)...")
                        await asyncio.sleep(2)

                if not otp_input:
                    # 调试：dump 页面上所有 input 的属性
                    debug_info = await page.evaluate("""() => {
                        const inputs = document.querySelectorAll('input');
                        return Array.from(inputs).map(el => ({
                            type: el.type, name: el.name, id: el.id,
                            placeholder: el.placeholder,
                            inputmode: el.inputMode,
                            autocomplete: el.autocomplete,
                            ariaLabel: el.getAttribute('aria-label'),
                            className: el.className.substring(0, 80),
                            dataTestId: el.getAttribute('data-testid'),
                            visible: el.offsetWidth > 0 && el.offsetHeight > 0,
                            tagPath: el.closest('[class]')?.className?.substring(0, 60) || ''
                        }));
                    }""")
                    log(f"未找到 OTP 输入框! 页面 input 元素 dump:", "err")
                    for info in debug_info:
                        log(f"  {info}", "err")
                    await browser.close()
                    callback_server.shutdown()
                    return _partial_result("OTP输入框未找到")

                log(f"已找到 OTP 输入框, 等待验证码 ({mail.__class__.__name__})...", "ok")
                otp_code = ""
                otp_deadline = time.time() + 90
                while time.time() < otp_deadline:
                    if cancel_check and cancel_check():
                        log("用户取消", "err")
                        await browser.close()
                        callback_server.shutdown()
                        return _partial_result("用户取消")
                    otp_code = mail.wait_otp(timeout=5, poll_interval=3)
                    if otp_code:
                        break
                if not otp_code:
                    log("OTP 等待超时!", "err")
                    await browser.close()
                    callback_server.shutdown()
                    return _partial_result("OTP超时")

                log(f"获取到验证码: {otp_code}", "ok")
                # 模拟人类从邮箱切回来的行为：先移动鼠标到页面中央区域
                await _human_delay(2, 4)
                try:
                    vp = page.viewport_size
                    await page.mouse.move(
                        vp["width"] * _random.uniform(0.3, 0.7),
                        vp["height"] * _random.uniform(0.3, 0.5),
                        steps=_random.randint(8, 20)
                    )
                    await asyncio.sleep(_random.uniform(0.3, 0.8))
                except Exception:
                    pass
                await _move_to_element(page, otp_input)
                await otp_input.click()
                await asyncio.sleep(_random.uniform(0.3, 0.6))
                # 逐字输入 OTP，不用 fill 避免 React 受控组件问题
                for ch in otp_code:
                    await page.keyboard.type(ch, delay=0)
                    await asyncio.sleep(_random.uniform(0.05, 0.15))
                await _human_delay(0.8, 1.5)

                # 提交 OTP，TES 可能首次拦截，增加重试间隔和行为模拟
                for attempt in range(5):
                    try:
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
                    except Exception:
                        await page.keyboard.press("Enter")
                    log(f"验证码已提交 ({attempt+1}/5)")
                    # 递增等待：TES 首次拦截后需要更长时间重新评估
                    wait_time = 3 + attempt * 2
                    await asyncio.sleep(wait_time)
                    new_state = await detect_state()
                    if new_state != "OTP":
                        log("OTP 验证通过", "ok")
                        state = new_state
                        break
                    # 如果还在 OTP 页面，检查是否有错误提示（TES 拦截）
                    try:
                        error_text = await page.evaluate("""() => {
                            const alerts = document.querySelectorAll('[role="alert"], [class*="error"], [class*="Error"]');
                            for (const el of alerts) {
                                const t = el.innerText.trim();
                                if (t && t.length > 3) return t;
                            }
                            return '';
                        }""")
                        if error_text:
                            log(f"TES 拦截 ({attempt+1}/5), 重新模拟输入...", "warn")
                            # 模拟人类看到错误后重新操作：点击输入框、清空、重新输入
                            await page.mouse.move(
                                _random.randint(200, 800), _random.randint(200, 500),
                                steps=_random.randint(8, 15)
                            )
                            await _human_delay(1.5, 3.0)
                            await _move_to_element(page, otp_input)
                            await otp_input.click()
                            await asyncio.sleep(_random.uniform(0.2, 0.4))
                            # 全选并删除，模拟 Ctrl+A + Delete
                            await page.keyboard.press("Control+a")
                            await asyncio.sleep(_random.uniform(0.1, 0.3))
                            await page.keyboard.press("Backspace")
                            await asyncio.sleep(_random.uniform(0.3, 0.6))
                            # 重新逐字输入
                            for ch in otp_code:
                                await page.keyboard.type(ch, delay=0)
                                await asyncio.sleep(_random.uniform(0.06, 0.18))
                            await _human_delay(0.8, 1.5)
                    except Exception:
                        pass

            # Phase 5: 密码设置
            if state not in ["DONE", "CONSENT", "CALLBACK"]:
                if state in ["UNKNOWN", "LOADING", "OTP"]:
                    log(f"等待页面过渡 (当前: {state})...", "info")
                    await asyncio.sleep(3)
                state = await wait_for_state(["PASSWORD", "CONSENT", "DONE", "CALLBACK"], timeout=30)
                if state == "CANCELLED":
                    await browser.close()
                    callback_server.shutdown()
                    return _partial_result("用户取消")
                log(f"进入状态: {state}", "info")

            if state == "PASSWORD":
                log("阶段 5: 设置密码")
                await _human_delay(1.5, 3.0)
                for _wait in range(10):
                    count = await page.locator('xpath=//input[@type="password"]').count()
                    if count >= 2:
                        break
                    await asyncio.sleep(1)
                for attempt in range(3):
                    try:
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
                    except Exception:
                        await asyncio.sleep(2)
                        continue
                    await asyncio.sleep(5)
                    new_state = await detect_state()
                    if new_state != "PASSWORD":
                        log("密码设置完成", "ok")
                        state = new_state
                        break

            # Phase 6: 授权确认
            if state not in ["DONE", "CALLBACK"]:
                state = await wait_for_state(["CONSENT", "DONE", "CALLBACK"], timeout=45)

            if state == "CANCELLED":
                await browser.close()
                callback_server.shutdown()
                return _partial_result("用户取消")
            if state == "CONSENT":
                log("阶段 6: 授权同意页")
                await asyncio.sleep(3)
                for attempt in range(10):
                    try:
                        clicked = await page.evaluate("""() => {
                            const buttons = Array.from(document.querySelectorAll('button'));
                            const visible = buttons.filter(b => b.offsetWidth > 0 && b.offsetHeight > 0);
                            for (const b of visible) {
                                const t = (b.innerText || '').toLowerCase();
                                if (t.includes('allow') || t.includes('authorize') || t.includes('accept') || t.includes('confirm')) {
                                    b.click(); return true;
                                }
                            }
                            if (visible.length > 0) { visible[visible.length - 1].click(); return true; }
                            return false;
                        }""")
                    except Exception:
                        log("授权后页面已导航", "ok")
                        state = "CALLBACK"
                        break
                    if clicked:
                        log("自动点击授权按钮", "ok")
                        await asyncio.sleep(4)
                        try:
                            new_state = await detect_state()
                        except Exception:
                            state = "CALLBACK"
                            break
                        if new_state != "CONSENT":
                            state = new_state
                            break
                    await asyncio.sleep(2)

            # 等待回调 code
            log("等待 OAuth 回调...")
            for i in range(30):
                if cancel_check and cancel_check():
                    log("用户取消", "err")
                    await browser.close()
                    callback_server.shutdown()
                    return _partial_result("用户取消")
                if authorization_code:
                    break
                current_url = page.url
                if "127.0.0.1:3128" in current_url or "localhost:3128" in current_url:
                    qs = parse_qs(urlparse(current_url).query)
                    authorization_code = qs.get("code", [""])[0]
                    if authorization_code:
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
        callback_server.shutdown()

    # Phase 7: Token 交换
    if not authorization_code:
        log("未获取到授权码!", "err")
        return _partial_result("未获取授权码")

    log("已获取授权码", "ok")
    log("正在交换 Token...")

    token_resp = s.post(f"{REG_OIDC}/token", json={
        "clientId": client_id,
        "clientSecret": client_secret,
        "grantType": "authorization_code",
        "code": authorization_code,
        "redirectUri": REG_REDIRECT_URI,
        "codeVerifier": code_verifier,
    }, timeout=25, verify=False)

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

    # 注入本地 Token + 随机机器码
    if auto_login:
        log("注入本地 Token...", "info")
        persist_tokens(client_id, client_secret, access_token, refresh_token, expires_in, log, email=email)
        machine_ids = inject_machine_ids(log)
        if skip_onboard:
            skip_onboarding(log)

    log("=" * 40, "ok")
    log("注册完成!", "ok")
    log(f"  Email: {email}", "ok")
    log(f"  Password: {password}", "ok")
    log("=" * 40, "ok")

    return {
        "email": email,
        "password": password,
        "full_name": full_name,
        "provider": "BuilderId",
        "authMethod": "IdC",
        "region": "us-east-1",
        "clientId": client_id,
        "clientSecret": client_secret,
        "clientIdHash": _sha1_hash(client_id),
        "accessToken": access_token,
        "refreshToken": refresh_token,
        "expiresAt": (datetime.now(timezone.utc) + timedelta(seconds=expires_in)).strftime("%Y/%m/%d %H:%M:%S"),
    }

