#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Kiro Pro 账号管理工具
功能: SQLite存储 + 账号导入导出 + Token刷新 + 额度查询 + 超额开启 + 本地注入
支持: Github / Google (Social) 和 BuilderId (IdC) 认证
"""

import json
import os
import sys
import stat
import asyncio
import base64
import hashlib
import secrets
import queue
import re
import sqlite3
import time
import threading
import urllib.request
import urllib.error
import urllib.parse
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlencode, urlparse

# When running as PyInstaller bundle, configure paths for bundled dependencies
if getattr(sys, 'frozen', False):
    _bundle_dir = Path(sys._MEIPASS) if hasattr(sys, '_MEIPASS') else Path(sys.executable).parent
    # Bundled browsers location
    _bundled_browsers = _bundle_dir / 'ms-playwright'
    if _bundled_browsers.exists():
        os.environ['PLAYWRIGHT_BROWSERS_PATH'] = str(_bundled_browsers)
    else:
        # Fallback to user's installed browsers
        _pw_browsers = Path.home() / 'AppData' / 'Local' / 'ms-playwright'
        if _pw_browsers.exists():
            os.environ['PLAYWRIGHT_BROWSERS_PATH'] = str(_pw_browsers)
    # For onedir mode, the exe dir has all packages
    _exe_dir = Path(sys.executable).parent
    if _exe_dir not in [Path(p) for p in sys.path]:
        sys.path.insert(0, str(_exe_dir))
else:
    # Non-frozen: set browsers path if not already set
    if 'PLAYWRIGHT_BROWSERS_PATH' not in os.environ:
        _pw_browsers = Path.home() / 'AppData' / 'Local' / 'ms-playwright'
        if _pw_browsers.exists():
            os.environ['PLAYWRIGHT_BROWSERS_PATH'] = str(_pw_browsers)


# ─── Constants ───────────────────────────────────────────────────────────────

KIRO_AUTH_ENDPOINT = "https://prod.us-east-1.auth.desktop.kiro.dev"
CODEWHISPERER_ENDPOINT = "https://q.us-east-1.amazonaws.com"
SSO_OIDC_ENDPOINT = "https://oidc.{region}.amazonaws.com"

FIXED_PROFILE_ARNS = {
    "BuilderId": "arn:aws:codewhisperer:us-east-1:638616132270:profile/AAAACCCCXXXX",
    "Github": "arn:aws:codewhisperer:us-east-1:699475941385:profile/EHGA3GRVQMUK",
    "Google": "arn:aws:codewhisperer:us-east-1:699475941385:profile/EHGA3GRVQMUK",
}

KIRO_CACHE_DIR = Path.home() / ".aws" / "sso" / "cache"

# ─── Registration Constants ─────────────────────────────────────────────────

SHIROMAIL_BASE = "https://shiromail.galiais.com"
SHIROMAIL_KEY = "sk_live_3fgiWLXZuS3dalfbGJV-uFgV"
SHIROMAIL_DOMAIN_ID = 4

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

# DB path: same directory as exe (frozen) or script
if getattr(sys, "frozen", False):
    APP_DIR = Path(sys.executable).parent
else:
    APP_DIR = Path(__file__).parent

DB_PATH = APP_DIR / "kiro_accounts.db"
CONFIG_PATH = APP_DIR / "kiro_config.json"


def load_config():
    if CONFIG_PATH.exists():
        try:
            return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def save_config(cfg):
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")


# ─── Database Layer ──────────────────────────────────────────────────────────

DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT,
    password TEXT DEFAULT '',
    provider TEXT,
    authMethod TEXT,
    accessToken TEXT,
    refreshToken TEXT,
    expiresAt TEXT,
    clientId TEXT,
    clientSecret TEXT,
    clientIdHash TEXT,
    region TEXT DEFAULT 'us-east-1',
    profileArn TEXT,
    userId TEXT,
    usageLimit INTEGER DEFAULT 0,
    currentUsage INTEGER DEFAULT 0,
    overageCap INTEGER DEFAULT 0,
    currentOverages INTEGER DEFAULT 0,
    overageStatus TEXT,
    overageCharges REAL DEFAULT 0.0,
    subscription TEXT DEFAULT '',
    lastQueryTime TEXT,
    createdAt TEXT DEFAULT (datetime('now','localtime')),
    updatedAt TEXT DEFAULT (datetime('now','localtime'))
);
"""


def get_db():
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(DB_SCHEMA)
    # Migration: add subscription column if missing
    cols = [r[1] for r in conn.execute("PRAGMA table_info(accounts)").fetchall()]
    if "subscription" not in cols:
        conn.execute("ALTER TABLE accounts ADD COLUMN subscription TEXT DEFAULT ''")
    if "password" not in cols:
        conn.execute("ALTER TABLE accounts ADD COLUMN password TEXT DEFAULT ''")
    conn.commit()
    return conn


def db_upsert_account(conn, data):
    """Insert or update account. Match by userId or email."""
    user_id = data.get("userId") or ""
    email = data.get("email") or ""

    existing = None
    if user_id:
        existing = conn.execute("SELECT id FROM accounts WHERE userId=?", (user_id,)).fetchone()
    if not existing and email:
        existing = conn.execute("SELECT id FROM accounts WHERE email=?", (email,)).fetchone()

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    password = data.get("password", "")

    if existing:
        # 只在有新密码时更新密码字段，避免覆盖已有密码
        if password:
            conn.execute("""
                UPDATE accounts SET
                    email=?, password=?, provider=?, authMethod=?, accessToken=?, refreshToken=?,
                    expiresAt=?, clientId=?, clientSecret=?, clientIdHash=?, region=?,
                    profileArn=?, userId=?, usageLimit=?, currentUsage=?, overageCap=?,
                    currentOverages=?, overageStatus=?, overageCharges=?, subscription=?,
                    lastQueryTime=?, updatedAt=?
                WHERE id=?
            """, (
                email, password, data.get("provider"), data.get("authMethod"),
                data.get("accessToken"), data.get("refreshToken"),
                data.get("expiresAt"), data.get("clientId"), data.get("clientSecret"),
                data.get("clientIdHash"), data.get("region", "us-east-1"),
                data.get("profileArn"), user_id,
                data.get("usageLimit", 0), data.get("currentUsage", 0),
                data.get("overageCap", 0), data.get("currentOverages", 0),
                data.get("overageStatus"), data.get("overageCharges", 0.0),
                data.get("subscription", ""), data.get("lastQueryTime"), now, existing["id"]
            ))
        else:
            conn.execute("""
                UPDATE accounts SET
                    email=?, provider=?, authMethod=?, accessToken=?, refreshToken=?,
                    expiresAt=?, clientId=?, clientSecret=?, clientIdHash=?, region=?,
                    profileArn=?, userId=?, usageLimit=?, currentUsage=?, overageCap=?,
                    currentOverages=?, overageStatus=?, overageCharges=?, subscription=?,
                    lastQueryTime=?, updatedAt=?
                WHERE id=?
            """, (
                email, data.get("provider"), data.get("authMethod"),
                data.get("accessToken"), data.get("refreshToken"),
                data.get("expiresAt"), data.get("clientId"), data.get("clientSecret"),
                data.get("clientIdHash"), data.get("region", "us-east-1"),
                data.get("profileArn"), user_id,
                data.get("usageLimit", 0), data.get("currentUsage", 0),
                data.get("overageCap", 0), data.get("currentOverages", 0),
                data.get("overageStatus"), data.get("overageCharges", 0.0),
                data.get("subscription", ""), data.get("lastQueryTime"), now, existing["id"]
            ))
    else:
        conn.execute("""
            INSERT INTO accounts (
                email, password, provider, authMethod, accessToken, refreshToken,
                expiresAt, clientId, clientSecret, clientIdHash, region,
                profileArn, userId, usageLimit, currentUsage, overageCap,
                currentOverages, overageStatus, overageCharges, subscription,
                lastQueryTime, createdAt, updatedAt
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            email, password, data.get("provider"), data.get("authMethod"),
            data.get("accessToken"), data.get("refreshToken"),
            data.get("expiresAt"), data.get("clientId"), data.get("clientSecret"),
            data.get("clientIdHash"), data.get("region", "us-east-1"),
            data.get("profileArn"), user_id,
            data.get("usageLimit", 0), data.get("currentUsage", 0),
            data.get("overageCap", 0), data.get("currentOverages", 0),
            data.get("overageStatus"), data.get("overageCharges", 0.0),
            data.get("subscription", ""), data.get("lastQueryTime"), now, now
        ))
    conn.commit()


def db_get_all(conn):
    return conn.execute("SELECT * FROM accounts ORDER BY id").fetchall()


def db_delete(conn, row_id):
    conn.execute("DELETE FROM accounts WHERE id=?", (row_id,))
    conn.commit()


def db_update_usage(conn, row_id, usage_data):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute("""
        UPDATE accounts SET
            usageLimit=?, currentUsage=?, overageCap=?, currentOverages=?,
            overageStatus=?, overageCharges=?, subscription=?, lastQueryTime=?, updatedAt=?
        WHERE id=?
    """, (
        usage_data.get("usageLimit", 0), usage_data.get("currentUsage", 0),
        usage_data.get("overageCap", 0), usage_data.get("currentOverages", 0),
        usage_data.get("overageStatus"), usage_data.get("overageCharges", 0.0),
        usage_data.get("subscription", ""), now, now, row_id
    ))
    conn.commit()


def db_update_token(conn, row_id, access_token, refresh_token, expires_at):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute("""
        UPDATE accounts SET accessToken=?, refreshToken=?, expiresAt=?, updatedAt=?
        WHERE id=?
    """, (access_token, refresh_token, expires_at, now, row_id))
    conn.commit()


# ─── API Layer ───────────────────────────────────────────────────────────────

def http_post(url, body, headers=None):
    all_headers = {"Content-Type": "application/json"}
    if headers:
        all_headers.update(headers)
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(), headers=all_headers, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return {"ok": True, "data": json.loads(resp.read()), "status": resp.status}
    except urllib.error.HTTPError as e:
        error_body = e.read().decode()
        try:
            err_data = json.loads(error_body)
        except Exception:
            err_data = {"raw": error_body}
        return {"ok": False, "error": err_data, "status": e.code}
    except Exception as e:
        return {"ok": False, "error": {"message": str(e)}, "status": 0}


def http_get(url, headers=None):
    all_headers = {}
    if headers:
        all_headers.update(headers)
    req = urllib.request.Request(url, headers=all_headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return {"ok": True, "data": json.loads(resp.read()), "status": resp.status}
    except urllib.error.HTTPError as e:
        error_body = e.read().decode()
        try:
            err_data = json.loads(error_body)
        except Exception:
            err_data = {"raw": error_body}
        return {"ok": False, "error": err_data, "status": e.code}
    except Exception as e:
        return {"ok": False, "error": {"message": str(e)}, "status": 0}


def refresh_social_token(refresh_token):
    url = f"{KIRO_AUTH_ENDPOINT}/refreshToken"
    body = {"refreshToken": refresh_token}
    result = http_post(url, body)
    if result["ok"]:
        d = result["data"]
        return {
            "accessToken": d["accessToken"],
            "refreshToken": d["refreshToken"],
            "expiresIn": d.get("expiresIn", 3600),
        }
    return None


def refresh_idc_token(client_id, client_secret, refresh_token, region="us-east-1"):
    url = f"{SSO_OIDC_ENDPOINT.format(region=region)}/token"
    body = {
        "clientId": client_id,
        "clientSecret": client_secret,
        "refreshToken": refresh_token,
        "grantType": "refresh_token",
    }
    result = http_post(url, body)
    if result["ok"]:
        d = result["data"]
        return {
            "accessToken": d["accessToken"],
            "refreshToken": d["refreshToken"],
            "expiresIn": d.get("expiresIn", 3600),
            "idToken": d.get("idToken", ""),
        }
    return None


def decode_jwt_email(token):
    """Try to extract email from a JWT token (access or id token)."""
    if not token:
        return "", ""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return "", ""
        payload = parts[1]
        payload += "=" * (4 - len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
        email = claims.get("email", "") or claims.get("preferred_username", "")
        user_id = claims.get("sub", "")
        return email, user_id
    except Exception:
        return "", ""


def get_userinfo_email(access_token, region="us-east-1"):
    """Try OIDC userinfo endpoint to get email for IdC/BuilderId accounts."""
    for base in [
        f"https://oidc.{region}.amazonaws.com",
        "https://identitystore.us-east-1.amazonaws.com",
    ]:
        url = f"{base}/userinfo"
        result = http_get(url, {"Authorization": f"Bearer {access_token}"})
        if result["ok"]:
            data = result["data"]
            email = data.get("email", "") or data.get("preferred_username", "") or data.get("name", "")
            user_id = data.get("sub", "")
            if email:
                return email, user_id
    return "", ""


def query_usage(access_token, profile_arn, require_email=False):
    params = {"profileArn": profile_arn}
    if require_email:
        params["isEmailRequired"] = "true"
    url = f"{CODEWHISPERER_ENDPOINT}/getUsageLimits?{urllib.parse.urlencode(params)}"
    headers = {"Authorization": f"Bearer {access_token}"}
    return http_get(url, headers)


def enable_overage(access_token, profile_arn):
    url = f"{CODEWHISPERER_ENDPOINT}/setUserPreference"
    headers = {"Authorization": f"Bearer {access_token}"}
    body = {"profileArn": profile_arn, "overageConfiguration": {"overageStatus": "ENABLED"}}
    return http_post(url, body, headers)


def list_available_models(access_token, profile_arn):
    """GET /ListAvailableModels - returns list of supported models."""
    params = {"origin": "AI_EDITOR", "profileArn": profile_arn}
    url = f"{CODEWHISPERER_ENDPOINT}/ListAvailableModels?{urllib.parse.urlencode(params)}"
    headers = {"Authorization": f"Bearer {access_token}"}
    all_models = []
    default_model = None
    while True:
        result = http_get(url, headers)
        if not result["ok"]:
            return {"ok": False, "models": [], "defaultModel": None, "error": result.get("error")}
        data = result["data"]
        all_models.extend(data.get("models", []))
        if not default_model and data.get("defaultModel"):
            default_model = data["defaultModel"]
        next_token = data.get("nextToken")
        if not next_token:
            break
        params["nextToken"] = next_token
        url = f"{CODEWHISPERER_ENDPOINT}/ListAvailableModels?{urllib.parse.urlencode(params)}"
    return {"ok": True, "models": all_models, "defaultModel": default_model}


def list_profiles(access_token):
    url = f"{CODEWHISPERER_ENDPOINT}/ListAvailableProfiles"
    headers = {"Authorization": f"Bearer {access_token}"}
    result = http_post(url, {}, headers)
    if result["ok"]:
        profiles = result["data"].get("profiles", [])
        if profiles:
            return profiles[0].get("arn")
    return None


# ─── Token Helpers ───────────────────────────────────────────────────────────

SUBSCRIPTION_DISPLAY = {
    "KIRO_PRO": "Pro",
    "KIRO_FREE": "Free",
    "KIRO_POWER": "Power",
    "KIRO_PRO_PLUS": "Pro+",
    "Q_DEVELOPER_STANDALONE_PRO": "Pro",
    "Q_DEVELOPER_STANDALONE_FREE": "Free",
    "Q_DEVELOPER_STANDALONE_POWER": "Power",
    "Q_DEVELOPER_STANDALONE_PRO_PLUS": "Pro+",
    "Q_DEVELOPER_STANDALONE": "Free",
}

# Kiro API 错误码映射 (来源: kiro-agent/q-client)
API_ERROR_MESSAGES = {
    "AccessDeniedException": "访问被拒绝",
    "FEATURE_NOT_SUPPORTED": "功能不支持 (账号类型不匹配)",
    "TEMPORARILY_SUSPENDED": "账号已被临时封禁",
    "ThrottlingException": "请求过于频繁",
    "INSUFFICIENT_MODEL_CAPACITY": "模型容量不足",
    "ServiceQuotaExceededException": "服务配额超限",
    "OVERAGE_REQUEST_LIMIT_EXCEEDED": "超额请求上限已达",
    "ValidationException": "请求参数无效",
    "INVALID_MODEL_ID": "无效的模型 ID",
    "InternalServerException": "服务器内部错误",
    "MODEL_TEMPORARILY_UNAVAILABLE": "模型暂时不可用",
    "UnsupportedClientVersionException": "客户端版本不支持",
    "HOURLY_REQUEST_COUNT": "已达每小时请求上限",
    "DAILY_REQUEST_COUNT": "已达每日请求上限",
    "WEEKLY_REQUEST_COUNT": "已达每周请求上限",
    "MONTHLY_REQUEST_COUNT": "已达每月请求上限",
    "USAGE_LIMIT_REACHED": "用量已达上限",
    "Operation not supported": "操作不支持 (Free套餐无法开启超额)",
}


def translate_api_error(err_data):
    """将 API 错误转为中文提示"""
    if isinstance(err_data, dict):
        msg = err_data.get("message") or err_data.get("Message") or ""
        reason = err_data.get("reason") or ""
        err_type = err_data.get("__type") or err_data.get("type") or ""
        for key, zh in API_ERROR_MESSAGES.items():
            if key in msg or key in reason or key in err_type:
                return zh
        return msg[:80] if msg else str(err_data)[:80]
    return str(err_data)[:80]


def format_subscription(raw):
    """Convert raw subscription title/type to display name."""
    if not raw:
        return "-"
    upper = raw.upper().replace(" ", "_")
    for key, display in SUBSCRIPTION_DISPLAY.items():
        if key in upper:
            return display
    if "PRO" in upper:
        return "Pro"
    if "FREE" in upper:
        return "Free"
    return raw


def is_token_expired(expires_at_str):
    """Check if token is expired or will expire within 5 minutes."""
    if not expires_at_str:
        return True
    for fmt in ("%Y-%m-%dT%H:%M:%S.000Z", "%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(expires_at_str, fmt)
            return dt < datetime.now() + timedelta(minutes=5)
        except ValueError:
            continue
    return True


def do_refresh_token(row):
    """Refresh token for a DB row. Returns (access_token, refresh_token, expires_at, error)."""
    auth_method = row["authMethod"]
    if auth_method == "social":
        result = refresh_social_token(row["refreshToken"])
        if result:
            expires_at = (datetime.now() + timedelta(seconds=result["expiresIn"])).strftime("%Y-%m-%d %H:%M:%S")
            return result["accessToken"], result["refreshToken"], expires_at, None
        return None, None, None, "Social Token 刷新失败"
    elif auth_method == "IdC":
        client_id = row["clientId"]
        client_secret = row["clientSecret"]
        region = row["region"] or "us-east-1"
        if not client_id or not client_secret:
            return None, None, None, "缺少 clientId/clientSecret"
        result = refresh_idc_token(client_id, client_secret, row["refreshToken"], region)
        if result:
            expires_at = (datetime.now() + timedelta(seconds=result["expiresIn"])).strftime("%Y-%m-%d %H:%M:%S")
            return result["accessToken"], result["refreshToken"], expires_at, None
        return None, None, None, "IdC Token 刷新失败"
    return None, None, None, f"未知认证方式: {auth_method}"


def get_valid_token(row, conn=None):
    """Get a valid access token, refreshing if needed. Optionally updates DB and subscription."""
    if not is_token_expired(row["expiresAt"]):
        return row["accessToken"], None
    access_token, refresh_token, expires_at, err = do_refresh_token(row)
    if err:
        return None, err
    if conn and row["id"]:
        db_update_token(conn, row["id"], access_token, refresh_token, expires_at)
        # Sync subscription after refresh
        _sync_subscription_after_refresh(conn, row, access_token)
    return access_token, None


def _sync_subscription_after_refresh(conn, row, access_token):
    """Query usage after token refresh to update subscription type."""
    provider = row["provider"] or ""
    profile_arn = row["profileArn"] or FIXED_PROFILE_ARNS.get(provider, "")
    if not profile_arn:
        profile_arn = list_profiles(access_token) or ""
    if not profile_arn:
        return
    result = query_usage(access_token, profile_arn)
    if result["ok"]:
        data = result["data"]
        bl = data.get("usageBreakdownList", [])
        b = bl[0] if bl else {}
        sub_info = data.get("subscriptionInfo", {})
        sub_raw = sub_info.get("subscriptionTitle", "") or sub_info.get("type", "") if sub_info else ""
        db_update_usage(conn, row["id"], {
            "usageLimit": int(b.get("usageLimit", b.get("usageLimitWithPrecision", 0))),
            "currentUsage": int(b.get("currentUsage", b.get("currentUsageWithPrecision", 0))),
            "overageCap": int(b.get("overageCap", b.get("overageCapWithPrecision", 0))),
            "currentOverages": int(b.get("currentOverages", b.get("currentOveragesWithPrecision", 0))),
            "overageStatus": data.get("overageConfiguration", {}).get("overageStatus", ""),
            "overageCharges": float(b.get("overageCharges", 0)),
            "subscription": sub_raw,
        })


# ─── Inject Logic ────────────────────────────────────────────────────────────

def parse_expires_for_inject(expires_str):
    if not expires_str:
        return (datetime.now() + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.000Z"):
        try:
            dt = datetime.strptime(expires_str, fmt)
            return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        except ValueError:
            continue
    return (datetime.now() + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def parse_client_secret_expiry(client_secret):
    try:
        parts = client_secret.split(".")
        payload = parts[1]
        payload += "=" * (4 - len(payload) % 4)
        decoded = json.loads(base64.urlsafe_b64decode(payload))
        serialized = json.loads(decoded["serialized"])
        ts = serialized.get("expirationTimestamp", 0)
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    except Exception:
        return (datetime.now() + timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def inject_account(row):
    """Inject account to local Kiro cache. row is a dict or sqlite3.Row."""
    KIRO_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    auth_method = row["authMethod"] or ""
    provider = row["provider"] or ""

    token_data = {
        "accessToken": row["accessToken"],
        "refreshToken": row["refreshToken"],
        "expiresAt": parse_expires_for_inject(row["expiresAt"]),
    }

    if auth_method == "social":
        token_data["authMethod"] = "social"
        token_data["provider"] = provider
    elif auth_method == "IdC":
        token_data["authMethod"] = "IdC"
        token_data["provider"] = provider
        token_data["region"] = row["region"] or "us-east-1"
        token_data["clientIdHash"] = row["clientIdHash"] or ""
    else:
        return False, f"不支持的认证方式: {auth_method}"

    token_path = KIRO_CACHE_DIR / "kiro-auth-token.json"
    with open(token_path, "w", encoding="utf-8") as f:
        json.dump(token_data, f, indent=2)
    try:
        os.chmod(token_path, stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        pass

    if auth_method == "IdC" and row["clientId"] and row["clientSecret"]:
        client_reg = {
            "clientId": row["clientId"],
            "clientSecret": row["clientSecret"],
            "expiresAt": parse_client_secret_expiry(row["clientSecret"]),
        }
        client_hash = row["clientIdHash"] or ""
        if client_hash:
            client_path = KIRO_CACHE_DIR / f"{client_hash}.json"
            with open(client_path, "w", encoding="utf-8") as f:
                json.dump(client_reg, f, indent=2)
            try:
                os.chmod(client_path, stat.S_IRUSR | stat.S_IWUSR)
            except Exception:
                pass

    return True, f"注入成功 ({provider}/{auth_method})"


def get_local_token_status():
    token_path = KIRO_CACHE_DIR / "kiro-auth-token.json"
    if not token_path.exists():
        return None
    try:
        with open(token_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


# ─── Import Helpers ──────────────────────────────────────────────────────────

def import_from_local_kiro(conn):
    """Read local kiro-auth-token.json and clientRegistration, query usage, save to DB."""
    token = get_local_token_status()
    if not token:
        return False, "未找到本地 kiro-auth-token.json"

    auth_method = token.get("authMethod", "")
    provider = token.get("provider", "")
    access_token = token.get("accessToken", "")
    refresh_token = token.get("refreshToken", "")
    expires_at = token.get("expiresAt", "")
    region = token.get("region", "us-east-1")
    client_id_hash = token.get("clientIdHash", "")

    client_id = ""
    client_secret = ""

    if auth_method == "IdC" and client_id_hash:
        client_path = KIRO_CACHE_DIR / f"{client_id_hash}.json"
        if client_path.exists():
            try:
                with open(client_path, "r", encoding="utf-8") as f:
                    client_data = json.load(f)
                client_id = client_data.get("clientId", "")
                client_secret = client_data.get("clientSecret", "")
            except Exception:
                pass

    # Normalize expiresAt
    norm_expires = expires_at
    if expires_at and "T" in expires_at:
        try:
            dt = datetime.strptime(expires_at, "%Y-%m-%dT%H:%M:%S.000Z")
            norm_expires = dt.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass

    # Determine profile ARN
    profile_arn = FIXED_PROFILE_ARNS.get(provider, "")
    if not profile_arn and access_token:
        profile_arn = list_profiles(access_token) or ""

    # Query usage
    usage_limit = 0
    current_usage = 0
    overage_cap = 0
    current_overages = 0
    overage_status = ""
    overage_charges = 0.0
    subscription = ""
    email = ""
    user_id = ""

    if access_token and profile_arn:
        result = query_usage(access_token, profile_arn, require_email=True)
        if result["ok"]:
            data = result["data"]
            # Extract email from userInfo in response
            user_info = data.get("userInfo", {})
            if user_info:
                email = user_info.get("email", "")
            # Extract subscription info
            sub_info = data.get("subscriptionInfo", {})
            if sub_info:
                subscription = sub_info.get("subscriptionTitle", "") or sub_info.get("type", "")
            breakdown_list = data.get("usageBreakdownList", [])
            if breakdown_list:
                b = breakdown_list[0]
                usage_limit = int(b.get("usageLimit", b.get("usageLimitWithPrecision", 0)))
                current_usage = int(b.get("currentUsage", b.get("currentUsageWithPrecision", 0)))
                overage_cap = int(b.get("overageCap", b.get("overageCapWithPrecision", 0)))
                current_overages = int(b.get("currentOverages", b.get("currentOveragesWithPrecision", 0)))
                overage_charges = float(b.get("overageCharges", 0))
            overage_cfg = data.get("overageConfiguration", {})
            overage_status = overage_cfg.get("overageStatus", "")

    # If email not from API response, try JWT decode (works for social)
    if not email:
        email, user_id = decode_jwt_email(access_token)

    # For IdC, access token is opaque; try refreshing to get idToken with email
    if not email and auth_method == "IdC" and client_id and client_secret and refresh_token:
        refresh_result = refresh_idc_token(client_id, client_secret, refresh_token, region)
        if refresh_result:
            access_token = refresh_result["accessToken"]
            refresh_token = refresh_result["refreshToken"]
            norm_expires = (datetime.now() + timedelta(seconds=refresh_result["expiresIn"])).strftime("%Y-%m-%d %H:%M:%S")
            id_token = refresh_result.get("idToken", "")
            if id_token:
                email, user_id = decode_jwt_email(id_token)

    # Still no email? Try OIDC userinfo endpoint
    if not email and access_token:
        email, user_id = get_userinfo_email(access_token, region)

    if not email:
        email = f"{provider}_{auth_method}_local"

    account_data = {
        "email": email,
        "provider": provider,
        "authMethod": auth_method,
        "accessToken": access_token,
        "refreshToken": refresh_token,
        "expiresAt": norm_expires,
        "clientId": client_id,
        "clientSecret": client_secret,
        "clientIdHash": client_id_hash,
        "region": region,
        "profileArn": profile_arn,
        "userId": user_id,
        "usageLimit": usage_limit,
        "currentUsage": current_usage,
        "overageCap": overage_cap,
        "currentOverages": current_overages,
        "overageStatus": overage_status,
        "overageCharges": overage_charges,
        "subscription": subscription,
        "lastQueryTime": datetime.now().strftime("%Y-%m-%d %H:%M:%S") if profile_arn else None,
    }

    db_upsert_account(conn, account_data)
    return True, f"导入成功: {email} ({provider})"


def import_from_json_file(conn, file_path):
    """Import accounts from JSON file (array of account objects).
    Returns (count, emails_list) for selective refresh.
    """
    with open(file_path, "r", encoding="utf-8") as f:
        accounts = json.load(f)

    if not isinstance(accounts, list):
        accounts = [accounts]

    imported = 0
    imported_emails = []
    for acc in accounts:
        usage_data = acc.get("usageData", {})
        breakdown_list = usage_data.get("usageBreakdownList", [])
        b = breakdown_list[0] if breakdown_list else {}

        overage_cfg = usage_data.get("overageConfiguration", {})

        email = acc.get("email", "")
        account_data = {
            "email": email,
            "provider": acc.get("provider", ""),
            "authMethod": acc.get("authMethod", ""),
            "accessToken": acc.get("accessToken", ""),
            "refreshToken": acc.get("refreshToken", ""),
            "expiresAt": acc.get("expiresAt", ""),
            "clientId": acc.get("clientId", ""),
            "clientSecret": acc.get("clientSecret", ""),
            "clientIdHash": acc.get("clientIdHash", ""),
            "region": acc.get("region", "us-east-1"),
            "profileArn": acc.get("profileArn", ""),
            "userId": acc.get("userId", ""),
            "usageLimit": int(b.get("usageLimit", b.get("usageLimitWithPrecision", 0))),
            "currentUsage": int(b.get("currentUsage", b.get("currentUsageWithPrecision", 0))),
            "overageCap": int(b.get("overageCap", b.get("overageCapWithPrecision", 0))),
            "currentOverages": int(b.get("currentOverages", b.get("currentOveragesWithPrecision", 0))),
            "overageStatus": overage_cfg.get("overageStatus", ""),
            "overageCharges": float(b.get("overageCharges", 0)),
            "lastQueryTime": None,
        }
        db_upsert_account(conn, account_data)
        imported += 1
        if email:
            imported_emails.append(email)

    return imported, imported_emails


def export_to_json(conn, file_path):
    """Export all accounts from DB to JSON file."""
    rows = db_get_all(conn)
    accounts = []
    for row in rows:
        acc = {
            "email": row["email"],
            "provider": row["provider"],
            "authMethod": row["authMethod"],
            "accessToken": row["accessToken"],
            "refreshToken": row["refreshToken"],
            "expiresAt": row["expiresAt"],
            "clientId": row["clientId"],
            "clientSecret": row["clientSecret"],
            "clientIdHash": row["clientIdHash"],
            "region": row["region"],
            "profileArn": row["profileArn"],
            "userId": row["userId"],
            "usageData": {
                "usageBreakdownList": [{
                    "usageLimit": row["usageLimit"],
                    "currentUsage": row["currentUsage"],
                    "overageCap": row["overageCap"],
                    "currentOverages": row["currentOverages"],
                    "overageCharges": row["overageCharges"],
                }],
                "overageConfiguration": {
                    "overageStatus": row["overageStatus"] or "",
                },
            },
        }
        accounts.append(acc)

    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(accounts, f, indent=2, ensure_ascii=False)
    return len(accounts)


# ─── GUI Application ─────────────────────────────────────────────────────────

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Kiro Pro 账号管理工具 | 仅供学习研究，禁止出售、贩卖、用于商业用途")
        self.geometry("1100x720")
        self.minsize(900, 600)
        self.configure(bg="#1a1a2e")

        self.conn = get_db()
        self.running = False
        self._lock = threading.Lock()
        self._auto_refresh_id = None

        self._setup_styles()
        self._build_ui()
        self._load_accounts_from_db()
        self._refresh_local_status()
        self._start_auto_refresh()

    def _setup_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        style.configure(".", background="#1a1a2e", foreground="#e0e0e0")
        style.configure("TFrame", background="#1a1a2e")
        style.configure("TLabelframe", background="#1a1a2e", foreground="#e0e0e0")
        style.configure("TLabelframe.Label", background="#1a1a2e", foreground="#00d2ff",
                        font=("Microsoft YaHei UI", 9, "bold"))
        style.configure("TLabel", background="#1a1a2e", foreground="#e0e0e0",
                        font=("Microsoft YaHei UI", 9))
        style.configure("Title.TLabel", font=("Microsoft YaHei UI", 14, "bold"), foreground="#00d2ff")
        style.configure("Stats.TLabel", font=("Microsoft YaHei UI", 9), foreground="#b0b0b0")
        style.configure("Status.TLabel", font=("Consolas", 9), foreground="#8b949e")

        style.configure("TButton", font=("Microsoft YaHei UI", 9), padding=(10, 5))
        style.map("TButton",
            background=[("active", "#16213e"), ("!active", "#0f3460")],
            foreground=[("active", "#ffffff"), ("!active", "#e0e0e0")],
        )
        style.configure("Green.TButton", font=("Microsoft YaHei UI", 9, "bold"))
        style.map("Green.TButton",
            background=[("active", "#1b8a5a"), ("!active", "#2ecc71")],
            foreground=[("active", "#ffffff"), ("!active", "#1a1a2e")],
        )
        style.configure("Orange.TButton", font=("Microsoft YaHei UI", 9, "bold"))
        style.map("Orange.TButton",
            background=[("active", "#d68910"), ("!active", "#f39c12")],
            foreground=[("active", "#ffffff"), ("!active", "#1a1a2e")],
        )
        style.configure("Red.TButton", font=("Microsoft YaHei UI", 9, "bold"))
        style.map("Red.TButton",
            background=[("active", "#c0392b"), ("!active", "#f85149")],
            foreground=[("active", "#ffffff"), ("!active", "#1a1a2e")],
        )

        style.configure("Treeview",
            background="#16213e", foreground="#e0e0e0", fieldbackground="#16213e",
            font=("Consolas", 9), rowheight=24,
        )
        style.configure("Treeview.Heading",
            background="#0f3460", foreground="#00d2ff",
            font=("Microsoft YaHei UI", 9, "bold"),
        )
        style.map("Treeview", background=[("selected", "#1a5276")])

        style.configure("TNotebook", background="#1a1a2e")
        style.configure("TNotebook.Tab", font=("Microsoft YaHei UI", 10), padding=(15, 5))
        style.map("TNotebook.Tab",
            background=[("selected", "#0f3460"), ("!selected", "#16213e")],
            foreground=[("selected", "#00d2ff"), ("!selected", "#8b949e")],
        )
        style.configure("TEntry",
            fieldbackground="#16213e", foreground="#e0e0e0", insertcolor="#e0e0e0",
            font=("Consolas", 9))
        style.configure("TCombobox",
            fieldbackground="#16213e", foreground="#e0e0e0",
            background="#0f3460", arrowcolor="#00d2ff",
            font=("Microsoft YaHei UI", 9))
        style.map("TCombobox",
            fieldbackground=[("readonly", "#16213e"), ("disabled", "#111122")],
            foreground=[("readonly", "#e0e0e0"), ("disabled", "#666666")],
            selectbackground=[("readonly", "#1a5276")],
            selectforeground=[("readonly", "#ffffff")],
        )
        self.option_add("*TCombobox*Listbox.background", "#16213e")
        self.option_add("*TCombobox*Listbox.foreground", "#e0e0e0")
        self.option_add("*TCombobox*Listbox.selectBackground", "#1a5276")
        self.option_add("*TCombobox*Listbox.selectForeground", "#ffffff")
        style.configure("TCheckbutton", background="#1a1a2e", foreground="#e0e0e0",
            font=("Microsoft YaHei UI", 9))
        style.map("TCheckbutton",
            background=[("active", "#1a1a2e"), ("!active", "#1a1a2e")],
            foreground=[("active", "#00d2ff"), ("!active", "#e0e0e0")],
            indicatorcolor=[("selected", "#00d2ff"), ("!selected", "#16213e")],
        )
        style.configure("Horizontal.TProgressbar", troughcolor="#16213e", background="#2ecc71")

    def _build_ui(self):
        header = ttk.Frame(self, padding=(20, 12))
        header.pack(fill="x")
        ttk.Label(header, text="Kiro Pro 账号管理工具", style="Title.TLabel").pack(side="left")
        self.lbl_db_path = ttk.Label(header, text=f"数据库: {DB_PATH.name}", style="Stats.TLabel")
        self.lbl_db_path.pack(side="right")

        warn_frame = tk.Frame(self, bg="#1a1a2e")
        warn_frame.pack(fill="x", padx=20)
        tk.Label(warn_frame, text="⚠ 本程序仅供学习研究使用，严禁出售、贩卖、传播或用于任何商业用途，违者后果自负",
                 bg="#1a1a2e", fg="#f85149", font=("Microsoft YaHei UI", 9, "bold")).pack(anchor="w")

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=15, pady=(0, 10))

        self._build_tab_accounts()
        self._build_tab_usage()
        self._build_tab_batch()
        self._build_tab_local()
        self._build_tab_register()
        self._build_tab_manual_login()

    # ─── Tab 1: 账号管理 ─────────────────────────────────────────────────
    def _build_tab_accounts(self):
        tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab, text="  账号管理  ")

        toolbar = ttk.Frame(tab)
        toolbar.pack(fill="x", pady=(0, 8))

        ttk.Button(toolbar, text="从本地Kiro导入",
                   command=self._import_local).pack(side="left", padx=(0, 5))
        ttk.Button(toolbar, text="从JSON导入",
                   command=self._import_json).pack(side="left", padx=5)
        ttk.Button(toolbar, text="导出JSON", style="Green.TButton",
                   command=self._export_json).pack(side="left", padx=5)
        ttk.Button(toolbar, text="删除选中", style="Red.TButton",
                   command=self._delete_selected).pack(side="left", padx=5)
        ttk.Button(toolbar, text="刷新选中",
                   command=self._refresh_selected_token).pack(side="left", padx=5)
        ttk.Button(toolbar, text="刷新全部",
                   command=self._refresh_all_tokens).pack(side="left", padx=5)
        ttk.Button(toolbar, text="健康检查", style="Orange.TButton",
                   command=self._health_check).pack(side="left", padx=5)

        toolbar2 = ttk.Frame(tab)
        toolbar2.pack(fill="x", pady=(0, 4))
        ttk.Button(toolbar2, text="全选",
                   command=self._select_all_accounts).pack(side="left", padx=(0, 5))
        ttk.Button(toolbar2, text="反选",
                   command=self._invert_selection).pack(side="left", padx=5)
        ttk.Button(toolbar2, text="复制选中JSON",
                   command=self._copy_selected_json).pack(side="left", padx=5)
        ttk.Button(toolbar2, text="复制选中邮箱",
                   command=self._copy_selected_emails).pack(side="left", padx=5)
        self.lbl_sel_info = ttk.Label(toolbar2, text="", style="Stats.TLabel")
        self.lbl_sel_info.pack(side="right")

        cfg = load_config()
        ttk.Label(toolbar, text="自动刷新:").pack(side="left", padx=(15, 0))
        self._auto_refresh_min = tk.StringVar(value=cfg.get("auto_refresh_min", "60"))
        ttk.Entry(toolbar, textvariable=self._auto_refresh_min, width=4).pack(side="left", padx=2)
        ttk.Label(toolbar, text="分钟").pack(side="left")
        def _on_refresh_change(*_):
            c = load_config()
            c["auto_refresh_min"] = self._auto_refresh_min.get().strip()
            save_config(c)
            self._start_auto_refresh()
        self._auto_refresh_min.trace_add("write", _on_refresh_change)

        self.lbl_acc_stats = ttk.Label(toolbar, text="", style="Stats.TLabel")
        self.lbl_acc_stats.pack(side="right")

        self.acc_progress = ttk.Progressbar(tab, mode="determinate",
                                            style="Horizontal.TProgressbar")
        self.acc_progress.pack(fill="x", pady=(0, 8))

        # PanedWindow: top = account tree, bottom = models + log
        paned = tk.PanedWindow(tab, orient=tk.VERTICAL, sashwidth=6,
                               bg="#1a1a2e", sashrelief="flat", opaqueresize=False)
        paned.pack(fill="both", expand=True)

        # Top pane: account tree
        table_frame = ttk.Frame(paned)
        columns = ("id", "email", "provider", "auth", "subscription", "overage", "usage", "expires", "status")
        self.acc_tree = ttk.Treeview(table_frame, columns=columns, show="headings",
                                     selectmode="extended")
        col_cfg = [
            ("id", "ID", 35), ("email", "邮箱", 180), ("provider", "登录方式", 70),
            ("auth", "认证类型", 60), ("subscription", "订阅", 80),
            ("overage", "超额状态", 75), ("usage", "用量", 90),
            ("expires", "Token过期", 130), ("status", "状态", 80),
        ]
        for cid, heading, width in col_cfg:
            self.acc_tree.heading(cid, text=heading)
            self.acc_tree.column(cid, width=width, minwidth=35)

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.acc_tree.yview)
        self.acc_tree.configure(yscrollcommand=scrollbar.set)
        self.acc_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        paned.add(table_frame, minsize=100)

        # Bottom pane: models + log
        bottom_frame = ttk.Frame(paned)

        # Models detail panel (collapsible)
        self._models_visible = tk.BooleanVar(value=False)
        self._models_cache = {}

        models_header = ttk.Frame(bottom_frame)
        models_header.pack(fill="x", pady=(4, 0))
        self.btn_models_toggle = ttk.Button(models_header, text="▶ 可用模型 (点击展开)",
                                            command=self._toggle_models_panel)
        self.btn_models_toggle.pack(side="left")
        ttk.Button(models_header, text="查询模型",
                   command=self._query_selected_models).pack(side="left", padx=8)

        self.models_frame = ttk.Frame(bottom_frame)
        self.models_text = tk.Text(self.models_frame, bg="#0d1117", fg="#e0e0e0",
                                   font=("Consolas", 9), insertbackground="#e0e0e0",
                                   relief="flat", wrap="word", height=8)
        models_scroll = ttk.Scrollbar(self.models_frame, orient="vertical",
                                      command=self.models_text.yview)
        self.models_text.configure(yscrollcommand=models_scroll.set)
        self.models_text.pack(side="left", fill="both", expand=True)
        models_scroll.pack(side="right", fill="y")
        self.models_text.tag_configure("title", foreground="#00d2ff", font=("Consolas", 9, "bold"))
        self.models_text.tag_configure("default", foreground="#2ecc71")
        self.models_text.tag_configure("model", foreground="#e0e0e0")
        self.models_text.tag_configure("dim", foreground="#8b949e")

        self.acc_tree.bind("<<TreeviewSelect>>", self._on_acc_select)
        self.acc_tree.bind("<Button-3>", self._on_acc_right_click)
        self.acc_tree.bind("<Double-1>", self._on_acc_double_click)
        self.acc_tree.bind("<Control-a>", lambda e: self._select_all_accounts())
        self.acc_tree.bind("<Control-c>", lambda e: self._copy_selected_json())
        self.acc_tree.bind("<Delete>", lambda e: self._delete_selected())

        # Log panel
        self._log_label = ttk.Label(bottom_frame, text="操作日志", style="Stats.TLabel")
        self._log_label.pack(anchor="w", pady=(8, 2))
        log_frame = ttk.Frame(bottom_frame)
        log_frame.pack(fill="both", expand=True)

        self.log_text = tk.Text(log_frame, bg="#0d1117", fg="#8b949e",
                                font=("Consolas", 9), insertbackground="#e0e0e0",
                                relief="flat", wrap="word", height=4)
        log_scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        log_scroll.pack(side="right", fill="y")

        self.log_text.tag_configure("info", foreground="#58a6ff")
        self.log_text.tag_configure("success", foreground="#2ecc71")
        self.log_text.tag_configure("error", foreground="#f85149")
        self.log_text.tag_configure("warn", foreground="#f39c12")

        paned.add(bottom_frame, minsize=80)

    # ─── Tab 2: 额度查询 ─────────────────────────────────────────────────
    def _build_tab_usage(self):
        tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab, text="  额度查询  ")

        toolbar = ttk.Frame(tab)
        toolbar.pack(fill="x", pady=(0, 8))

        ttk.Button(toolbar, text="查询所有账号额度", style="Green.TButton",
                   command=self._query_all_usage).pack(side="left", padx=(0, 5))
        ttk.Button(toolbar, text="查询选中账号",
                   command=self._query_selected_usage).pack(side="left", padx=5)
        self.lbl_usage_stats = ttk.Label(toolbar, text="", style="Stats.TLabel")
        self.lbl_usage_stats.pack(side="right")

        self.usage_progress = ttk.Progressbar(tab, mode="determinate",
                                              style="Horizontal.TProgressbar")
        self.usage_progress.pack(fill="x", pady=(0, 8))

        table_frame = ttk.Frame(tab)
        table_frame.pack(fill="both", expand=True)

        columns = ("id", "email", "provider", "subscription", "used", "limit", "overage_used",
                   "overage_cap", "overage_cost", "overage_status")
        self.usage_tree = ttk.Treeview(table_frame, columns=columns, show="headings",
                                       selectmode="browse")
        usage_col_cfg = [
            ("id", "ID", 35), ("email", "邮箱", 170), ("provider", "登录方式", 65),
            ("subscription", "订阅", 60), ("used", "已用额度", 70), ("limit", "总额度", 65),
            ("overage_used", "超额已用", 70), ("overage_cap", "超额上限", 70),
            ("overage_cost", "费用($)", 70), ("overage_status", "超额状态", 75),
        ]
        for cid, heading, width in usage_col_cfg:
            self.usage_tree.heading(cid, text=heading)
            self.usage_tree.column(cid, width=width, minwidth=35)

        usage_scroll = ttk.Scrollbar(table_frame, orient="vertical",
                                     command=self.usage_tree.yview)
        self.usage_tree.configure(yscrollcommand=usage_scroll.set)
        self.usage_tree.pack(side="left", fill="both", expand=True)
        usage_scroll.pack(side="right", fill="y")

        # Detail panel
        ttk.Label(tab, text="详细信息", style="Stats.TLabel").pack(anchor="w", pady=(8, 2))
        detail_frame = ttk.Frame(tab)
        detail_frame.pack(fill="x")

        self.usage_detail = tk.Text(detail_frame, bg="#0d1117", fg="#8b949e",
                                    font=("Consolas", 9), insertbackground="#e0e0e0",
                                    relief="flat", wrap="word", height=6)
        detail_scroll = ttk.Scrollbar(detail_frame, orient="vertical",
                                      command=self.usage_detail.yview)
        self.usage_detail.configure(yscrollcommand=detail_scroll.set)
        self.usage_detail.pack(side="left", fill="both", expand=True)
        detail_scroll.pack(side="right", fill="y")

        self.usage_detail.tag_configure("key", foreground="#00d2ff")
        self.usage_detail.tag_configure("val", foreground="#e0e0e0")
        self.usage_detail.tag_configure("warn", foreground="#f39c12")
        self.usage_detail.tag_configure("ok", foreground="#2ecc71")

        self.usage_tree.bind("<<TreeviewSelect>>", self._on_usage_select)

    # ─── Tab 3: 批量操作 ─────────────────────────────────────────────────
    def _build_tab_batch(self):
        tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab, text="  批量操作  ")

        toolbar = ttk.Frame(tab)
        toolbar.pack(fill="x", pady=(0, 8))

        ttk.Button(toolbar, text="批量开启超额", style="Green.TButton",
                   command=self._batch_enable_overage).pack(side="left", padx=(0, 5))
        ttk.Button(toolbar, text="注入选中账号到本地", style="Orange.TButton",
                   command=self._inject_selected).pack(side="left", padx=5)

        self.lbl_batch_stats = ttk.Label(toolbar, text="", style="Stats.TLabel")
        self.lbl_batch_stats.pack(side="right")

        self.batch_progress = ttk.Progressbar(tab, mode="determinate",
                                              style="Horizontal.TProgressbar")
        self.batch_progress.pack(fill="x", pady=(0, 8))

        # Batch table
        table_frame = ttk.Frame(tab)
        table_frame.pack(fill="both", expand=True)

        columns = ("id", "email", "provider", "operation", "result")
        self.batch_tree = ttk.Treeview(table_frame, columns=columns, show="headings",
                                       selectmode="extended")
        batch_col_cfg = [
            ("id", "ID", 35), ("email", "邮箱", 220), ("provider", "登录方式", 80),
            ("operation", "操作", 120), ("result", "结果", 300),
        ]
        for cid, heading, width in batch_col_cfg:
            self.batch_tree.heading(cid, text=heading)
            self.batch_tree.column(cid, width=width, minwidth=35)

        batch_scroll = ttk.Scrollbar(table_frame, orient="vertical",
                                     command=self.batch_tree.yview)
        self.batch_tree.configure(yscrollcommand=batch_scroll.set)
        self.batch_tree.pack(side="left", fill="both", expand=True)
        batch_scroll.pack(side="right", fill="y")

        # Batch log
        ttk.Label(tab, text="批量操作日志", style="Stats.TLabel").pack(anchor="w", pady=(8, 2))
        blog_frame = ttk.Frame(tab)
        blog_frame.pack(fill="x")

        self.batch_log = tk.Text(blog_frame, bg="#0d1117", fg="#8b949e",
                                 font=("Consolas", 9), insertbackground="#e0e0e0",
                                 relief="flat", wrap="word", height=6)
        blog_scroll = ttk.Scrollbar(blog_frame, orient="vertical",
                                    command=self.batch_log.yview)
        self.batch_log.configure(yscrollcommand=blog_scroll.set)
        self.batch_log.pack(side="left", fill="both", expand=True)
        blog_scroll.pack(side="right", fill="y")

        self.batch_log.tag_configure("info", foreground="#58a6ff")
        self.batch_log.tag_configure("success", foreground="#2ecc71")
        self.batch_log.tag_configure("error", foreground="#f85149")
        self.batch_log.tag_configure("warn", foreground="#f39c12")

    # ─── Tab 4: 本地状态 ─────────────────────────────────────────────────
    def _build_tab_local(self):
        tab = ttk.Frame(self.notebook, padding=15)
        self.notebook.add(tab, text="  本地状态  ")

        info_frame = ttk.LabelFrame(tab, text="当前 Kiro 本地 Token", padding=15)
        info_frame.pack(fill="x", pady=(0, 10))

        self.status_text = tk.Text(info_frame, bg="#0d1117", fg="#e0e0e0",
                                   font=("Consolas", 10), relief="flat",
                                   wrap="word", height=12)
        self.status_text.pack(fill="both", expand=True)
        self.status_text.tag_configure("key", foreground="#00d2ff")
        self.status_text.tag_configure("val", foreground="#e0e0e0")
        self.status_text.tag_configure("ok", foreground="#2ecc71")
        self.status_text.tag_configure("expired", foreground="#f85149")

        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill="x", pady=10)
        ttk.Button(btn_frame, text="刷新状态",
                   command=self._refresh_local_status).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="刷新本地Token", style="Green.TButton",
                   command=self._refresh_local_token).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="清除本地Token", style="Red.TButton",
                   command=self._clear_local_token).pack(side="left", padx=5)

        path_frame = ttk.Frame(tab)
        path_frame.pack(fill="x", pady=(10, 0))
        ttk.Label(path_frame, text=f"存储路径: {KIRO_CACHE_DIR}",
                  style="Stats.TLabel").pack(anchor="w")

    # ─── Tab 5: 自动注册 ─────────────────────────────────────────────────
    def _build_tab_register(self):
        tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab, text="  自动注册  ")

        # Options row
        opts_frame = ttk.Frame(tab)
        opts_frame.pack(fill="x", pady=(0, 8))

        self._reg_headless = tk.BooleanVar(value=True)
        self._reg_auto_login = tk.BooleanVar(value=True)
        self._reg_skip_onboard = tk.BooleanVar(value=True)
        self._reg_pro_trial = tk.BooleanVar(value=True)
        self._reg_import_no_trial = tk.BooleanVar(value=False)
        self._reg_use_roxy = tk.BooleanVar(value=False)

        ttk.Checkbutton(opts_frame, text="无头模式", variable=self._reg_headless).pack(side="left", padx=(0, 12))
        ttk.Checkbutton(opts_frame, text="自动登录", variable=self._reg_auto_login).pack(side="left", padx=(0, 12))
        ttk.Checkbutton(opts_frame, text="跳过引导", variable=self._reg_skip_onboard).pack(side="left", padx=(0, 12))
        ttk.Checkbutton(opts_frame, text="Pro试用订阅", variable=self._reg_pro_trial).pack(side="left", padx=(0, 12))
        ttk.Checkbutton(opts_frame, text="无试用仍入库", variable=self._reg_import_no_trial).pack(side="left", padx=(0, 12))
        ttk.Checkbutton(opts_frame, text="指纹浏览器", variable=self._reg_use_roxy).pack(side="left", padx=(0, 12))

        btn_frame = ttk.Frame(opts_frame)
        btn_frame.pack(side="right")
        self._reg_start_btn = ttk.Button(btn_frame, text="开始注册", style="Green.TButton",
                                         command=self._reg_start)
        self._reg_start_btn.pack(side="left", padx=(0, 5))
        self._reg_pro_only_btn = ttk.Button(btn_frame, text="仅订阅Pro", style="Orange.TButton",
                                            command=self._reg_pro_only)
        self._reg_pro_only_btn.pack(side="left", padx=(0, 5))
        self._reg_stop_btn = ttk.Button(btn_frame, text="停止", style="Red.TButton",
                                        command=self._reg_stop, state="disabled")
        self._reg_stop_btn.pack(side="left")

        # 邮件服务配置
        mail_frame = ttk.LabelFrame(tab, text="邮件服务配置", padding=(8, 4))
        mail_frame.pack(fill="x", pady=(0, 8))

        cfg = load_config()

        # 服务选择行
        row0 = ttk.Frame(mail_frame)
        row0.pack(fill="x", pady=2)
        ttk.Label(row0, text="服务:", width=8).pack(side="left")
        self._reg_mail_provider = tk.StringVar(value=cfg.get("mail_provider", "shiromail"))
        self._reg_provider_combo = ttk.Combobox(row0, textvariable=self._reg_mail_provider, width=16, state="readonly")
        from mail_providers import list_providers
        _providers = list_providers()
        self._reg_provider_combo["values"] = [p["display_name"] for p in _providers]
        self._reg_provider_name_map = {p["display_name"]: p["name"] for p in _providers}
        self._reg_provider_display_map = {p["name"]: p["display_name"] for p in _providers}
        # 设置当前显示值
        current_provider = cfg.get("mail_provider", "shiromail")
        self._reg_mail_provider.set(self._reg_provider_display_map.get(current_provider, "ShiroMail"))
        self._reg_provider_combo.pack(side="left", padx=4)
        ttk.Label(row0, text="(切换后需重新填写配置)", foreground="#8b949e").pack(side="left", padx=4)

        row1 = ttk.Frame(mail_frame)
        row1.pack(fill="x", pady=2)
        ttk.Label(row1, text="API URL:", width=8).pack(side="left")
        self._reg_mail_url = tk.StringVar(value=cfg.get("mail_url", ""))
        ttk.Entry(row1, textvariable=self._reg_mail_url, width=45).pack(side="left", padx=(4, 12))
        ttk.Label(row1, text="域名:").pack(side="left")
        self._reg_mail_domain_id = tk.StringVar(value=cfg.get("mail_domain_id", ""))
        self._reg_domain_combo = ttk.Combobox(row1, textvariable=self._reg_mail_domain_id, width=20, state="readonly")
        self._reg_domain_combo.pack(side="left", padx=4)
        self._reg_domain_map = {}
        ttk.Button(row1, text="刷新", width=4, command=self._reg_refresh_domains).pack(side="left", padx=2)

        row2 = ttk.Frame(mail_frame)
        row2.pack(fill="x", pady=2)
        ttk.Label(row2, text="API Key:", width=8).pack(side="left")
        self._reg_mail_key = tk.StringVar(value=cfg.get("mail_key", ""))
        self._reg_mail_key_entry = ttk.Entry(row2, textvariable=self._reg_mail_key, width=45, show="*")
        self._reg_mail_key_entry.pack(side="left", padx=4)

        def _on_provider_change(*_):
            display = self._reg_mail_provider.get()
            name = self._reg_provider_name_map.get(display, "shiromail")
            if name == "shiromail":
                self._reg_mail_key_entry.configure(state="normal")
                self._reg_domain_combo.configure(state="readonly")
        self._reg_mail_provider.trace_add("write", _on_provider_change)
        _on_provider_change()

        # EFunCard CDK 配置 (Pro试用订阅)
        cdk_frame = ttk.LabelFrame(tab, text="EFunCard CDK (Pro试用订阅)", padding=(8, 4))
        cdk_frame.pack(fill="x", pady=(0, 8))

        cdk_row = ttk.Frame(cdk_frame)
        cdk_row.pack(fill="x", pady=2)
        ttk.Label(cdk_row, text="CDK码:", width=8).pack(side="left")
        self._reg_cdk_code = tk.StringVar(value=cfg.get("cdk_code", ""))
        ttk.Entry(cdk_row, textvariable=self._reg_cdk_code, width=45).pack(side="left", padx=4)
        ttk.Label(cdk_row, text="(格式: US-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX)", foreground="#8b949e").pack(side="left", padx=4)

        yc_row = ttk.Frame(cdk_frame)
        yc_row.pack(fill="x", pady=2)
        ttk.Label(yc_row, text="YesCaptcha:", width=8).pack(side="left")
        self._reg_yescaptcha_key = tk.StringVar(value=cfg.get("yescaptcha_key", ""))
        ttk.Entry(yc_row, textvariable=self._reg_yescaptcha_key, width=45).pack(side="left", padx=4)
        ttk.Label(yc_row, text="(API Key, 用于 hCaptcha 自动求解)", foreground="#8b949e").pack(side="left", padx=4)

        # RoxyBrowser 指纹浏览器配置
        roxy_row = ttk.Frame(cdk_frame)
        roxy_row.pack(fill="x", pady=2)
        ttk.Label(roxy_row, text="Roxy Key:", width=8).pack(side="left")
        self._reg_roxy_key = tk.StringVar(value=cfg.get("roxy_api_key", ""))
        ttk.Entry(roxy_row, textvariable=self._reg_roxy_key, width=45).pack(side="left", padx=4)
        ttk.Label(roxy_row, text="(RoxyBrowser API Key, 勾选'指纹浏览器'时使用)", foreground="#8b949e").pack(side="left", padx=4)

        # 值变化时自动保存
        def _save_mail_config(*_):
            domain_val = self._reg_mail_domain_id.get().strip()
            if hasattr(self, '_reg_domain_map') and domain_val in self._reg_domain_map:
                domain_val = self._reg_domain_map[domain_val]
            provider_display = self._reg_mail_provider.get()
            provider_name = self._reg_provider_name_map.get(provider_display, "shiromail")
            save_config({
                "mail_provider": provider_name,
                "mail_url": self._reg_mail_url.get().strip(),
                "mail_key": self._reg_mail_key.get().strip(),
                "mail_domain_id": domain_val,
                "cdk_code": self._reg_cdk_code.get().strip(),
                "yescaptcha_key": self._reg_yescaptcha_key.get().strip(),
                "roxy_api_key": self._reg_roxy_key.get().strip(),
                "auto_refresh_min": self._auto_refresh_min.get().strip(),
            })
        self._reg_mail_provider.trace_add("write", _save_mail_config)
        self._reg_mail_url.trace_add("write", _save_mail_config)
        self._reg_mail_key.trace_add("write", _save_mail_config)
        self._reg_mail_domain_id.trace_add("write", _save_mail_config)
        self._reg_cdk_code.trace_add("write", _save_mail_config)
        self._reg_yescaptcha_key.trace_add("write", _save_mail_config)
        self._reg_roxy_key.trace_add("write", _save_mail_config)

        # Terminal output
        term_frame = ttk.Frame(tab)
        term_frame.pack(fill="both", expand=True)

        self._reg_term = tk.Text(term_frame, bg="#0d1117", fg="#c9d1d9",
                                 font=("Consolas", 10), insertbackground="#c9d1d9",
                                 relief="flat", wrap="word")
        term_scroll = ttk.Scrollbar(term_frame, orient="vertical", command=self._reg_term.yview)
        self._reg_term.configure(yscrollcommand=term_scroll.set)
        self._reg_term.pack(side="left", fill="both", expand=True)
        term_scroll.pack(side="right", fill="y")

        self._reg_term.tag_configure("info", foreground="#58a6ff")
        self._reg_term.tag_configure("ok", foreground="#2ecc71")
        self._reg_term.tag_configure("err", foreground="#f85149")
        self._reg_term.tag_configure("dbg", foreground="#8b949e")
        self._reg_term.tag_configure("highlight", foreground="#f0e68c")

        # Queue for thread-safe log delivery
        self._reg_queue = queue.Queue()
        self._reg_running = False
        self._reg_cancel = False

    # ─── Tab 5 Actions: 自动注册 ─────────────────────────────────────────
    def _reg_log(self, msg, level="info"):
        """Thread-safe log to registration terminal via queue."""
        self._reg_queue.put((msg, level))

    def _reg_poll_queue(self):
        """Poll the queue and write messages to the terminal widget."""
        has_msg = False
        try:
            while True:
                msg, level = self._reg_queue.get_nowait()
                has_msg = True
                ts = datetime.now().strftime("%H:%M:%S")
                prefix = {"info": "[*]", "ok": "[+]", "err": "[-]", "dbg": "[~]"}.get(level, "[?]")
                tag = level if level in ("info", "ok", "err", "dbg") else "info"
                self._reg_term.insert("end", f"{ts} {prefix} {msg}\n", tag)
                self._reg_term.see("end")
        except Exception:
            pass
        if self._reg_running or has_msg:
            self.after(100, self._reg_poll_queue)

    def _reg_start(self):
        """Start the registration process in a background thread."""
        try:
            self._reg_start_inner()
        except Exception as e:
            import traceback
            try:
                self._reg_term.delete("1.0", "end")
                self._reg_term.insert("end", f"启动失败: {e}\n\n", "err")
                self._reg_term.insert("end", traceback.format_exc(), "dbg")
            except Exception:
                messagebox.showerror("注册错误", f"启动失败: {e}\n\n{traceback.format_exc()}")

    def _reg_start_inner(self):
        if self._reg_running:
            return
        # Check dependencies
        missing = []
        dep_errors = []
        try:
            import curl_cffi  # noqa: F401
        except Exception as e:
            missing.append("curl_cffi")
            dep_errors.append(f"curl_cffi: {e}")
        try:
            import playwright  # noqa: F401
        except Exception as e:
            missing.append("playwright")
            dep_errors.append(f"playwright: {e}")
        try:
            import playwright_stealth  # noqa: F401
        except Exception as e:
            missing.append("playwright-stealth")
            dep_errors.append(f"playwright_stealth: {e}")
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
        except Exception as e:
            missing.append("cryptography")
            dep_errors.append(f"cryptography: {e}")

        if missing:
            self._reg_term.delete("1.0", "end")
            self._reg_term.insert("end", "缺少依赖包，请先安装:\n\n", "err")
            cmd = f"pip install {' '.join(missing)}"
            self._reg_term.insert("end", f"  {cmd}\n\n", "highlight")
            if "playwright" in missing:
                self._reg_term.insert("end", "  playwright install chromium\n\n", "highlight")
            if dep_errors:
                self._reg_term.insert("end", "详细错误:\n", "dbg")
                for err in dep_errors:
                    self._reg_term.insert("end", f"  {err}\n", "dbg")
            self._reg_term.insert("end", "\n注意: 此功能需要从 Python 环境运行 (python main.py)，\n", "info")
            self._reg_term.insert("end", "PyInstaller 打包的 exe 不包含这些依赖。\n", "info")
            return

        # Check playwright browser is installed
        try:
            from playwright._impl._driver import compute_driver_executable
            driver_exec = compute_driver_executable()
            if not Path(driver_exec).exists():
                raise FileNotFoundError(driver_exec)
        except Exception:
            try:
                import playwright._impl._driver as _drv
                browsers_path = Path(_drv.__file__).parent.parent / "driver" / "package" / ".local-browsers"
                if not browsers_path.exists():
                    user_browsers = Path.home() / "AppData" / "Local" / "ms-playwright"
                    if not user_browsers.exists():
                        self._reg_term.delete("1.0", "end")
                        self._reg_term.insert("end", "Playwright 浏览器未安装，请运行:\n\n", "err")
                        self._reg_term.insert("end", "  playwright install chromium\n", "highlight")
                        return
            except Exception:
                pass

        self._reg_running = True
        self._reg_cancel = False
        self._reg_term.delete("1.0", "end")
        self._reg_term.insert("end", f"{datetime.now().strftime('%H:%M:%S')} [*] 正在启动注册流程...\n", "info")
        self._reg_start_btn.configure(state="disabled")
        self._reg_stop_btn.configure(state="normal")

        self.after(100, self._reg_poll_queue)

        headless = self._reg_headless.get()
        auto_login = self._reg_auto_login.get()
        skip_onboard = self._reg_skip_onboard.get()
        pro_trial = self._reg_pro_trial.get()
        import_no_trial = self._reg_import_no_trial.get()
        use_roxy = self._reg_use_roxy.get()

        MAX_RETRY = 5

        def _check_account_health(result):
            """检测账号健康状态。返回 (status, reason)
            status: "ok" | "banned" | "no_trial"
            """
            access_token = result.get("accessToken", "")
            if not access_token:
                return "ok", ""
            profile_arn = FIXED_PROFILE_ARNS.get("BuilderId", "")
            # 1) 刷新 token 验证账号存活
            client_id = result.get("clientId", "")
            client_secret = result.get("clientSecret", "")
            refresh_token = result.get("refreshToken", "")
            if client_id and client_secret and refresh_token:
                refreshed = refresh_idc_token(client_id, client_secret, refresh_token)
                if refreshed is None:
                    return "banned", "token 刷新失败 (账号已被封禁)"
                access_token = refreshed["accessToken"]
            # 2) 查询 usage 检测封禁
            usage = query_usage(access_token, profile_arn)
            if not usage["ok"]:
                err_data = usage.get("error", {})
                err_str = str(err_data)
                if "TEMPORARILY_SUSPENDED" in err_str:
                    return "banned", "账号已被临时封禁 (TEMPORARILY_SUSPENDED)"
                if usage.get("status") == 403:
                    return "banned", f"访问被拒绝 (HTTP 403)"
            # 3) 检查是否有免费试用
            if pro_trial:
                import kiro_subscribe
                subs = kiro_subscribe.list_available_subscriptions(access_token, profile_arn, log=self._reg_log)
                if subs.get("ok"):
                    plans = subs.get("plans", [])
                    pro_plan = None
                    for p in plans:
                        qt = p.get("qSubscriptionType", "")
                        if "PRO" in qt.upper() and "PLUS" not in qt.upper():
                            pro_plan = p
                            break
                    if not pro_plan and plans:
                        pro_plan = plans[0]
                    if pro_plan:
                        pricing = pro_plan.get("pricing", {})
                        amount = pricing.get("amount", -1)
                        if amount is not None and float(amount) > 0:
                            return "no_trial", f"该账号无免费试用 (价格: {amount} {pricing.get('currency', 'USD')})"
            return "ok", ""

        def _do_import_and_subscribe(result, loop):
            """入库 + 订阅流程"""
            import random
            try:
                self._reg_import_to_db(result)
                self._reg_queue.put(("账号已自动导入数据库", "ok"))
                self._refresh_after_import(result.get("email", ""), self._reg_queue)
            except Exception as e:
                self._reg_queue.put((f"导入数据库失败: {e}", "err"))
            self.after(0, self._load_accounts_from_db)

            if pro_trial and result.get("accessToken"):
                self._reg_queue.put(("", "info"))
                warmup = random.randint(30, 90)
                self._reg_queue.put((f"预热等待 {warmup}s，模拟正常使用间隔...", "info"))
                time.sleep(warmup)
                self._reg_queue.put(("开始 Pro 试用订阅...", "info"))
                try:
                    loop.run_until_complete(
                        self._reg_pro_trial_subscribe(result, loop)
                    )
                except Exception as e:
                    err_str = str(e)
                    if "closed" in err_str.lower():
                        self._reg_queue.put(("支付页面意外关闭", "err"))
                    elif "timeout" in err_str.lower():
                        self._reg_queue.put(("支付操作超时", "err"))
                    else:
                        self._reg_queue.put((f"Pro 试用订阅失败: {err_str[:80]}", "err"))
            elif pro_trial and not result.get("accessToken"):
                self._reg_queue.put(("无 Token，跳过 Pro 订阅", "warn"))

        def _worker():
            import traceback as _tb
            import random
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                for attempt in range(1, MAX_RETRY + 1):
                    if self._reg_cancel:
                        self._reg_queue.put(("用户取消，停止重试", "warn"))
                        break
                    if attempt > 1:
                        wait = random.randint(10, 30)
                        self._reg_queue.put((f"等待 {wait}s 后开始第 {attempt}/{MAX_RETRY} 次注册...", "info"))
                        time.sleep(wait)
                    self._reg_queue.put((f"[{attempt}/{MAX_RETRY}] 注册线程已启动，正在初始化...", "info"))
                    try:
                        result = loop.run_until_complete(
                            self._reg_async_main(headless, auto_login, skip_onboard, use_roxy=use_roxy)
                        )
                    except Exception as e:
                        self._reg_queue.put((f"注册异常: {e}", "err"))
                        self._reg_queue.put((_tb.format_exc(), "dbg"))
                        continue

                    if not result or not result.get("email"):
                        self._reg_queue.put(("注册流程结束 (未获取到结果)", "err"))
                        continue

                    self._reg_queue.put((f"Email: {result['email']}", "highlight"))
                    self._reg_queue.put((f"Password: {result['password']}", "highlight"))

                    # 账号健康检测
                    self._reg_queue.put(("正在检测账号状态...", "info"))
                    status, reason = _check_account_health(result)

                    if status == "banned":
                        self._reg_queue.put((f"[-] {reason}, 不入库", "err"))
                        if attempt < MAX_RETRY:
                            self._reg_queue.put(("账号被封禁，将自动重新注册...", "warn"))
                        continue

                    if status == "no_trial":
                        self._reg_queue.put((f"[-] {reason}", "warn"))
                        if import_no_trial:
                            self._reg_queue.put(("无试用但用户选择仍入库，执行入库+订阅...", "info"))
                            _do_import_and_subscribe(result, loop)
                        else:
                            self._reg_queue.put(("跳过入库 (可勾选'无试用仍入库'改变此行为)", "info"))
                        if attempt < MAX_RETRY:
                            self._reg_queue.put(("将自动重新注册以获取试用账号...", "warn"))
                        continue

                    # 账号正常
                    is_incomplete = result.get("incomplete", False)
                    if is_incomplete:
                        self._reg_queue.put((f"[-] 注册未完成 ({result.get('failReason', '')}), 不入库", "err"))
                        if attempt < MAX_RETRY:
                            self._reg_queue.put(("将自动重新注册...", "warn"))
                        continue
                    self._reg_queue.put(("注册完成! 账号状态正常", "ok"))
                    _do_import_and_subscribe(result, loop)
                    break
                else:
                    self._reg_queue.put((f"已达最大重试次数 ({MAX_RETRY})，停止", "err"))
                loop.close()
            except Exception as e:
                self._reg_queue.put((f"注册异常: {e}", "err"))
                try:
                    self._reg_queue.put((_tb.format_exc(), "dbg"))
                except Exception:
                    pass
            finally:
                self._reg_running = False
                self.after(0, lambda: self._reg_start_btn.configure(state="normal"))
                self.after(0, lambda: self._reg_stop_btn.configure(state="disabled"))

        threading.Thread(target=_worker, daemon=True).start()

    def _reg_refresh_domains(self):
        """从邮件服务获取可用域名列表"""
        from mail_providers import get_provider
        base_url = self._reg_mail_url.get().strip().rstrip("/")
        api_key = self._reg_mail_key.get().strip()
        provider_display = self._reg_mail_provider.get()
        provider_name = self._reg_provider_name_map.get(provider_display, "shiromail")
        if not base_url:
            from tkinter import messagebox
            messagebox.showwarning("提示", "请先填写 API URL")
            return
        if provider_name == "shiromail" and not api_key:
            from tkinter import messagebox
            messagebox.showwarning("提示", "请先填写 API Key")
            return
        try:
            kwargs = {"base_url": base_url}
            if provider_name == "shiromail":
                kwargs["api_key"] = api_key
            provider = get_provider(provider_name, **kwargs)
            domains = provider.list_domains()
            if domains:
                self._reg_domain_map = {}
                display_list = []
                for d in domains:
                    domain_name = d.get("domain", "")
                    domain_id = d.get("id", "")
                    if domain_name and domain_id:
                        self._reg_domain_map[domain_name] = domain_id
                        display_list.append(domain_name)
                self._reg_domain_combo["values"] = display_list
                current = self._reg_mail_domain_id.get().strip()
                if current and current in [v for v in self._reg_domain_map.values()]:
                    for name, did in self._reg_domain_map.items():
                        if did == current:
                            self._reg_mail_domain_id.set(name)
                            break
                elif display_list and not current:
                    self._reg_mail_domain_id.set(display_list[0])
                self._reg_domain_combo.configure(state="readonly")
            else:
                from tkinter import messagebox
                messagebox.showinfo("提示", "未获取到域名列表")
        except Exception as e:
            from tkinter import messagebox
            messagebox.showerror("错误", f"请求失败: {e}")

    def _reg_stop(self):
        """Signal the registration to abort."""
        self._reg_cancel = True
        self._reg_log("用户请求停止...", "err")

    def _reg_pro_only(self):
        """跳过注册，直接用数据库中最新账号执行 Pro 试用订阅"""
        if self._reg_running:
            return
        # 从数据库取最新账号
        rows = db_get_all(self.conn)
        if not rows:
            from tkinter import messagebox
            messagebox.showwarning("提示", "数据库中无账号，请先注册")
            return
        # 取最后一条（最新注册的）
        row = rows[-1]
        access_token, err = get_valid_token(row, self.conn)
        if not access_token:
            from tkinter import messagebox
            messagebox.showerror("错误", f"Token 无效: {err}\n请先刷新或重新注册")
            return

        self._reg_running = True
        self._reg_cancel = False
        self._reg_term.delete("1.0", "end")
        self._reg_term.insert("end", f"{datetime.now().strftime('%H:%M:%S')} [*] 仅执行 Pro 试用订阅...\n", "info")
        self._reg_term.insert("end", f"  账号: {row['email']}\n", "info")
        self._reg_start_btn.configure(state="disabled")
        self._reg_pro_only_btn.configure(state="disabled")
        self._reg_stop_btn.configure(state="normal")
        self.after(100, self._reg_poll_queue)

        result = {
            "email": row["email"],
            "accessToken": access_token,
            "provider": row["provider"] or "BuilderId",
        }

        def _worker():
            try:
                import traceback as _tb
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                self._reg_queue.put(("开始 Pro 试用订阅...", "info"))
                loop.run_until_complete(self._reg_pro_trial_subscribe(result, loop))
                loop.close()
            except Exception as e:
                err_str = str(e)
                if "closed" in err_str.lower():
                    self._reg_queue.put(("支付页面意外关闭，请重试", "err"))
                elif "timeout" in err_str.lower():
                    self._reg_queue.put(("支付操作超时，请检查网络后重试", "err"))
                else:
                    self._reg_queue.put((f"Pro 试用订阅失败: {err_str[:80]}", "err"))
            finally:
                self._reg_running = False
                self.after(0, lambda: self._reg_start_btn.configure(state="normal"))
                self.after(0, lambda: self._reg_pro_only_btn.configure(state="normal"))
                self.after(0, lambda: self._reg_stop_btn.configure(state="disabled"))

        threading.Thread(target=_worker, daemon=True).start()

    def _reg_import_to_db(self, result):
        """Import a successful registration result into the SQLite DB."""
        account_data = {
            "email": result["email"],
            "password": result.get("password", ""),
            "provider": result.get("provider", "BuilderId"),
            "authMethod": result.get("authMethod", "IdC"),
            "accessToken": result.get("accessToken", ""),
            "refreshToken": result.get("refreshToken", ""),
            "expiresAt": result.get("expiresAt", ""),
            "clientId": result.get("clientId", ""),
            "clientSecret": result.get("clientSecret", ""),
            "clientIdHash": result.get("clientIdHash", ""),
            "region": result.get("region", "us-east-1"),
            "profileArn": FIXED_PROFILE_ARNS.get("BuilderId", ""),
            "userId": "",
            "usageLimit": 0,
            "currentUsage": 0,
            "overageCap": 0,
            "currentOverages": 0,
            "overageStatus": "",
            "overageCharges": 0.0,
            "subscription": "",
            "lastQueryTime": None,
        }
        db_upsert_account(self.conn, account_data)

    async def _reg_async_main(self, headless=True, auto_login=True, skip_onboard=True, use_roxy=False):
        """调用 kiro_register 或 roxy_register 模块执行完整注册流程"""
        from mail_providers import get_provider
        mail_url = self._reg_mail_url.get().strip() or None
        mail_key = self._reg_mail_key.get().strip() or None
        mail_domain_val = self._reg_mail_domain_id.get().strip() or None
        if mail_domain_val and hasattr(self, '_reg_domain_map') and mail_domain_val in self._reg_domain_map:
            mail_domain_id = self._reg_domain_map[mail_domain_val]
        else:
            mail_domain_id = mail_domain_val
        # 根据选择的服务创建 provider 实例
        provider_display = self._reg_mail_provider.get()
        provider_name = self._reg_provider_name_map.get(provider_display, "shiromail")
        provider_kwargs = {"base_url": mail_url or ""}
        if provider_name == "shiromail":
            provider_kwargs["api_key"] = mail_key or ""
            provider_kwargs["domain_id"] = mail_domain_id
        mail_instance = get_provider(provider_name, **provider_kwargs)

        if use_roxy:
            from roxy_register import register_with_roxy
            roxy_key = self._reg_roxy_key.get().strip()
            if not roxy_key:
                self._reg_log("未填写 RoxyBrowser API Key!", "err")
                return None
            return await register_with_roxy(
                api_key=roxy_key,
                headless=headless,
                auto_login=auto_login,
                skip_onboard=skip_onboard,
                mail_provider_instance=mail_instance,
                log=self._reg_log,
                cancel_check=lambda: self._reg_cancel,
            )
        else:
            import kiro_register
            return await kiro_register.register(
                headless=headless,
                auto_login=auto_login,
                skip_onboard=skip_onboard,
                mail_provider_instance=mail_instance,
                log=self._reg_log,
                cancel_check=lambda: self._reg_cancel,
            )

    async def _reg_pro_trial_subscribe(self, result, loop):
        """注册完成后自动订阅 Pro 试用 (使用 EFunCard 虚拟信用卡)"""
        import kiro_subscribe
        import os as _os
        from stripe_pay import auto_pay

        # 确保 YesCaptcha key 可用
        cfg = load_config()
        yescaptcha_key = self._reg_yescaptcha_key.get().strip()
        if not yescaptcha_key:
            log("未填写 YesCaptcha API Key，hCaptcha 将无法自动求解", "warn")
        else:
            _os.environ["YESCAPTCHA_API_KEY"] = yescaptcha_key

        access_token = result.get("accessToken", "")
        profile_arn = FIXED_PROFILE_ARNS.get("BuilderId", "")
        log = self._reg_log
        cdk_code = self._reg_cdk_code.get().strip()

        if not cdk_code:
            log("未填写 CDK 码，跳过 Pro 试用订阅", "err")
            return

        # Step 1: 查询可用套餐
        subs = kiro_subscribe.list_available_subscriptions(access_token, profile_arn, log=log)
        if not subs.get("ok"):
            log("无法获取订阅套餐列表", "err")
            return

        # 找到 KIRO_PRO 套餐
        plans = subs.get("plans", [])
        pro_type = None
        for p in plans:
            qt = p.get("qSubscriptionType", "")
            if "PRO" in qt.upper() and "PLUS" not in qt.upper():
                pro_type = qt
                break
        if not pro_type and plans:
            pro_type = plans[0].get("qSubscriptionType", "KIRO_PRO")
        if not pro_type:
            pro_type = "KIRO_PRO"

        log(f"订阅类型: {pro_type}", "info")

        # Step 2: 获取 Stripe 支付 URL
        token_result = kiro_subscribe.create_subscription_token(
            access_token, profile_arn, pro_type, log=log
        )
        if not token_result.get("ok") or not token_result.get("url"):
            log("无法获取支付 URL", "err")
            return

        payment_url = token_result["url"]
        log(f"支付 URL: {payment_url[:80]}...", "info")

        # Step 3: 使用 EFunCard + Stripe 自动支付
        captcha_cfg = {"yescaptcha_key": yescaptcha_key}
        pay_result = await auto_pay(
            payment_url, cdk_code, captcha_config=captcha_cfg, headless=True, log=log
        )

        if pay_result and pay_result.get("ok"):
            log("Pro 试用订阅成功!", "ok")
            try:
                rows = db_get_all(self.conn)
                for row in rows:
                    if row["email"] == result["email"]:
                        self.conn.execute(
                            "UPDATE accounts SET subscription=? WHERE id=?",
                            ("Pro", row["id"])
                        )
                        self.conn.commit()
                        break
                self.after(0, self._load_accounts_from_db)
            except Exception:
                pass
        else:
            log(f"Pro 试用订阅未完成: {pay_result}", "err")

    # ─── Tab 6: 手动登录 ─────────────────────────────────────────────────
    def _build_tab_manual_login(self):
        tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab, text="  手动登录  ")

        # 选项行
        opts_frame = ttk.Frame(tab)
        opts_frame.pack(fill="x", pady=(0, 8))

        self._ml_headless = tk.BooleanVar(value=False)
        self._ml_auto_login = tk.BooleanVar(value=True)
        self._ml_clear_session = tk.BooleanVar(value=True)

        ttk.Checkbutton(opts_frame, text="无头模式", variable=self._ml_headless).pack(side="left", padx=(0, 12))
        ttk.Checkbutton(opts_frame, text="自动登录", variable=self._ml_auto_login).pack(side="left", padx=(0, 12))
        ttk.Checkbutton(opts_frame, text="清除旧登录数据", variable=self._ml_clear_session).pack(side="left", padx=(0, 12))

        # 登录方式按钮
        method_frame = ttk.LabelFrame(tab, text="选择登录方式", padding=10)
        method_frame.pack(fill="x", pady=(0, 8))

        btn_row = ttk.Frame(method_frame)
        btn_row.pack(fill="x")

        self._ml_method = tk.StringVar(value="builderid")

        ttk.Button(btn_row, text="Google", style="Green.TButton",
                   command=lambda: self._ml_launch("google")).pack(side="left", padx=(0, 8), pady=4)
        ttk.Button(btn_row, text="GitHub", style="Green.TButton",
                   command=lambda: self._ml_launch("github")).pack(side="left", padx=(0, 8), pady=4)
        ttk.Button(btn_row, text="AWS Builder ID", style="Green.TButton",
                   command=lambda: self._ml_launch("builderid")).pack(side="left", padx=(0, 8), pady=4)
        ttk.Button(btn_row, text="IAM Identity Center", style="Green.TButton",
                   command=lambda: self._ml_launch("iam")).pack(side="left", padx=(0, 8), pady=4)

        self._ml_stop_btn = ttk.Button(btn_row, text="停止", style="Red.TButton",
                                       command=self._ml_stop, state="disabled")
        self._ml_stop_btn.pack(side="right", padx=(8, 0), pady=4)

        # 终端输出
        term_frame = ttk.Frame(tab)
        term_frame.pack(fill="both", expand=True)

        self._ml_term = tk.Text(term_frame, bg="#0d1117", fg="#c9d1d9",
                                font=("Consolas", 9), wrap="word", height=15)
        ml_scroll = ttk.Scrollbar(term_frame, orient="vertical", command=self._ml_term.yview)
        self._ml_term.configure(yscrollcommand=ml_scroll.set)
        self._ml_term.pack(side="left", fill="both", expand=True)
        ml_scroll.pack(side="right", fill="y")

        self._ml_term.tag_configure("info", foreground="#58a6ff")
        self._ml_term.tag_configure("ok", foreground="#2ecc71")
        self._ml_term.tag_configure("err", foreground="#f85149")
        self._ml_term.tag_configure("dbg", foreground="#8b949e")

        self._ml_queue = queue.Queue()
        self._ml_running = False
        self._ml_cancel = False

    # ─── Tab 6 Actions: 手动登录 ─────────────────────────────────────────
    def _ml_log(self, msg, level="info"):
        self._ml_queue.put((msg, level))

    def _ml_poll_queue(self):
        has_msg = False
        try:
            while True:
                msg, level = self._ml_queue.get_nowait()
                has_msg = True
                ts = datetime.now().strftime("%H:%M:%S")
                prefix = {"info": "[*]", "ok": "[+]", "err": "[-]", "dbg": "[~]"}.get(level, "[?]")
                tag = level if level in ("info", "ok", "err", "dbg") else "info"
                self._ml_term.insert("end", f"{ts} {prefix} {msg}\n", tag)
                self._ml_term.see("end")
        except Exception:
            pass
        if self._ml_running or has_msg:
            self.after(100, self._ml_poll_queue)

    def _ml_launch(self, method):
        if self._ml_running:
            return
        self._ml_running = True
        self._ml_cancel = False
        self._ml_term.delete("1.0", "end")
        self._ml_term.insert("end", f"{datetime.now().strftime('%H:%M:%S')} [*] 正在启动 {method} 登录...\n", "info")
        self._ml_stop_btn.configure(state="normal")
        self.after(100, self._ml_poll_queue)

        headless = self._ml_headless.get()
        auto_login = self._ml_auto_login.get()
        clear_session = self._ml_clear_session.get()

        def _worker():
            try:
                import kiro_login
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                result = loop.run_until_complete(
                    kiro_login.manual_login(
                        method=method,
                        headless=headless,
                        auto_login=auto_login,
                        clear_session=clear_session,
                        log=self._ml_log,
                        cancel_check=lambda: self._ml_cancel,
                    )
                )
                loop.close()
                if result:
                    self._ml_queue.put(("登录成功! 正在查询账号信息...", "ok"))
                    # 用和本地导入相同的逻辑获取真实邮箱和用量
                    access_token = result.get("accessToken", "")
                    refresh_token_val = result.get("refreshToken", "")
                    client_id = result.get("clientId", "")
                    client_secret = result.get("clientSecret", "")
                    provider = result.get("provider", "BuilderId")
                    region = result.get("region", "us-east-1")
                    client_id_hash = result.get("clientIdHash", "")

                    profile_arn = FIXED_PROFILE_ARNS.get(provider, "")
                    if not profile_arn and access_token:
                        profile_arn = list_profiles(access_token) or ""

                    email = ""
                    user_id = ""
                    usage_limit = 0
                    current_usage = 0
                    overage_cap = 0
                    current_overages = 0
                    overage_status = ""
                    overage_charges = 0.0
                    subscription = ""

                    if access_token and profile_arn:
                        usage_result = query_usage(access_token, profile_arn, require_email=True)
                        if usage_result["ok"]:
                            data = usage_result["data"]
                            user_info = data.get("userInfo", {})
                            if user_info:
                                email = user_info.get("email", "")
                            sub_info = data.get("subscriptionInfo", {})
                            if sub_info:
                                subscription = sub_info.get("subscriptionTitle", "") or sub_info.get("type", "")
                            breakdown_list = data.get("usageBreakdownList", [])
                            if breakdown_list:
                                b = breakdown_list[0]
                                usage_limit = int(b.get("usageLimit", b.get("usageLimitWithPrecision", 0)))
                                current_usage = int(b.get("currentUsage", b.get("currentUsageWithPrecision", 0)))
                                overage_cap = int(b.get("overageCap", b.get("overageCapWithPrecision", 0)))
                                current_overages = int(b.get("currentOverages", b.get("currentOveragesWithPrecision", 0)))
                                overage_charges = float(b.get("overageCharges", 0))
                            overage_cfg = data.get("overageConfiguration", {})
                            overage_status = overage_cfg.get("overageStatus", "")

                    if not email:
                        email, user_id = decode_jwt_email(access_token)

                    if not email and client_id and client_secret and refresh_token_val:
                        refresh_result = refresh_idc_token(client_id, client_secret, refresh_token_val, region)
                        if refresh_result:
                            access_token = refresh_result["accessToken"]
                            refresh_token_val = refresh_result["refreshToken"]
                            id_token = refresh_result.get("idToken", "")
                            if id_token:
                                email, user_id = decode_jwt_email(id_token)

                    if not email and access_token:
                        email, user_id = get_userinfo_email(access_token, region)

                    if not email:
                        email = result.get("email", f"{provider}_unknown")

                    self._ml_queue.put((f"Email: {email}", "ok"))
                    if subscription:
                        self._ml_queue.put((f"订阅: {subscription}", "ok"))
                    if usage_limit:
                        self._ml_queue.put((f"用量: {current_usage}/{usage_limit}", "ok"))

                    expires_at = result.get("expiresAt", "")
                    if expires_at and "/" in expires_at:
                        try:
                            dt = datetime.strptime(expires_at, "%Y/%m/%d %H:%M:%S")
                            expires_at = dt.strftime("%Y-%m-%d %H:%M:%S")
                        except ValueError:
                            pass

                    account_data = {
                        "email": email,
                        "provider": provider,
                        "authMethod": result.get("authMethod", "IdC"),
                        "accessToken": access_token,
                        "refreshToken": refresh_token_val,
                        "expiresAt": expires_at,
                        "clientId": client_id,
                        "clientSecret": client_secret,
                        "clientIdHash": client_id_hash,
                        "region": region,
                        "profileArn": profile_arn,
                        "userId": user_id,
                        "usageLimit": usage_limit,
                        "currentUsage": current_usage,
                        "overageCap": overage_cap,
                        "currentOverages": current_overages,
                        "overageStatus": overage_status,
                        "overageCharges": overage_charges,
                        "subscription": subscription,
                        "lastQueryTime": datetime.now().strftime("%Y-%m-%d %H:%M:%S") if profile_arn else None,
                    }
                    try:
                        db_upsert_account(self.conn, account_data)
                        self._ml_queue.put(("账号已导入数据库", "ok"))
                    except Exception as e:
                        self._ml_queue.put((f"导入数据库失败: {e}", "err"))
                    self.after(0, self._load_accounts_from_db)
                else:
                    self._ml_queue.put(("登录流程结束 (未获取到结果)", "err"))
            except Exception as e:
                self._ml_queue.put((f"登录异常: {e}", "err"))
                try:
                    import traceback
                    self._ml_queue.put((traceback.format_exc(), "dbg"))
                except Exception:
                    pass
            finally:
                self._ml_running = False
                self.after(0, lambda: self._ml_stop_btn.configure(state="disabled"))

        threading.Thread(target=_worker, daemon=True).start()

    def _ml_stop(self):
        self._ml_cancel = True
        self._ml_log("用户请求停止...", "err")

    # ─── Logging ─────────────────────────────────────────────────────────
    def _log(self, msg, tag="info"):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert("end", f"[{ts}] {msg}\n", tag)
        self.log_text.see("end")

    def _blog(self, msg, tag="info"):
        ts = datetime.now().strftime("%H:%M:%S")
        self.batch_log.insert("end", f"[{ts}] {msg}\n", tag)
        self.batch_log.see("end")

    # ─── Data Loading ────────────────────────────────────────────────────
    def _load_accounts_from_db(self):
        for item in self.acc_tree.get_children():
            self.acc_tree.delete(item)

        rows = db_get_all(self.conn)
        for row in rows:
            usage_str = f"{row['currentUsage']}/{row['usageLimit']}" if row['usageLimit'] else "-"
            expires = row["expiresAt"] or "无"
            expired = is_token_expired(expires)
            status = "已过期" if expired else "有效"
            overage = row["overageStatus"] or "未开启"
            sub = format_subscription(row["subscription"])

            self.acc_tree.insert("", "end", iid=str(row["id"]), values=(
                row["id"], row["email"] or "", row["provider"] or "",
                row["authMethod"] or "", sub, overage, usage_str, expires, status
            ))

        count = len(rows)
        providers = {}
        for r in rows:
            p = r["provider"] or "未知"
            providers[p] = providers.get(p, 0) + 1
        prov_str = "  ".join(f"{k}:{v}" for k, v in providers.items())
        self.lbl_acc_stats.configure(text=f"共 {count} 个账号  {prov_str}")

    # ─── Tab 1 Actions ───────────────────────────────────────────────────
    def _refresh_after_import(self, email="", queue=None):
        """导入后立即刷新 token 并同步订阅信息"""
        log = queue.put if queue else lambda m, *_: self._log(m)
        try:
            rows = db_get_all(self.conn)
            for row in rows:
                if email and row["email"] != email:
                    continue
                if not row["refreshToken"]:
                    continue
                at, rt, ea, err = do_refresh_token(row)
                if err:
                    log((f"刷新 Token 失败 ({row['email']}): {err}", "err"))
                    continue
                db_update_token(self.conn, row["id"], at, rt, ea)
                _sync_subscription_after_refresh(self.conn, row, at)
                log((f"Token 已刷新: {row['email']}", "ok"))
                if not email:
                    break
        except Exception as e:
            if queue:
                log((f"刷新异常: {e}", "err"))

    def _import_local(self):
        self._log("正在从本地 Kiro 导入...")
        def _do():
            ok, msg = import_from_local_kiro(self.conn)
            if ok:
                self.after(0, lambda: self._log(msg, "success"))
            else:
                self.after(0, lambda: self._log(msg, "error"))
            self.after(0, self._load_accounts_from_db)
        threading.Thread(target=_do, daemon=True).start()

    def _import_json(self):
        path = filedialog.askopenfilename(
            title="选择 JSON 账号文件",
            filetypes=[("JSON 文件", "*.json"), ("所有文件", "*.*")],
        )
        if not path:
            return
        self._log(f"正在导入: {Path(path).name}")
        def _do():
            try:
                count, emails = import_from_json_file(self.conn, path)
                self.after(0, lambda: self._log(f"成功导入 {count} 个账号", "success"))
                self.after(0, self._load_accounts_from_db)
                if emails:
                    self._refresh_imported_parallel(emails)
            except Exception as e:
                self.after(0, lambda: self._log(f"导入失败: {e}", "error"))
            self.after(0, self._load_accounts_from_db)
        threading.Thread(target=_do, daemon=True).start()

    def _refresh_imported_parallel(self, emails):
        """并行刷新指定邮箱列表的账号 token"""
        from concurrent.futures import ThreadPoolExecutor, as_completed
        rows = db_get_all(self.conn)
        targets = [r for r in rows if r["email"] in emails and r["refreshToken"]]
        if not targets:
            return

        def _refresh_one(row):
            try:
                at, rt, ea, err = do_refresh_token(row)
                if err:
                    return row["email"], False, err
                db_update_token(self.conn, row["id"], at, rt, ea)
                _sync_subscription_after_refresh(self.conn, row, at)
                return row["email"], True, None
            except Exception as e:
                return row["email"], False, str(e)

        refreshed = 0
        with ThreadPoolExecutor(max_workers=min(8, len(targets))) as pool:
            futures = {pool.submit(_refresh_one, r): r for r in targets}
            for fut in as_completed(futures):
                email, ok, err = fut.result()
                if ok:
                    refreshed += 1
                else:
                    self.after(0, lambda e=email, er=err: self._log(f"刷新失败 ({e}): {er}", "warn"))
        if refreshed:
            self.after(0, lambda: self._log(f"已并行刷新 {refreshed}/{len(targets)} 个导入账号", "success"))
            self.after(0, self._load_accounts_from_db)

    def _refresh_all_tokens_silent(self):
        """静默刷新所有账号 token"""
        rows = db_get_all(self.conn)
        refreshed = 0
        for row in rows:
            if not row["refreshToken"]:
                continue
            try:
                at, rt, ea, err = do_refresh_token(row)
                if not err:
                    db_update_token(self.conn, row["id"], at, rt, ea)
                    _sync_subscription_after_refresh(self.conn, row, at)
                    refreshed += 1
            except Exception:
                pass
        if refreshed:
            self.after(0, lambda: self._log(f"已刷新 {refreshed} 个账号 Token", "success"))
        self.after(0, self._load_accounts_from_db)

    def _start_auto_refresh(self):
        """启动自动刷新定时器"""
        if self._auto_refresh_id:
            self.after_cancel(self._auto_refresh_id)
            self._auto_refresh_id = None
        try:
            minutes = int(self._auto_refresh_min.get().strip() or "0")
        except ValueError:
            minutes = 0
        if minutes > 0:
            ms = minutes * 60 * 1000
            self._auto_refresh_id = self.after(ms, self._auto_refresh_tick)

    def _auto_refresh_tick(self):
        """定时刷新回调"""
        self._auto_refresh_id = None
        def _do():
            self._refresh_all_tokens_silent()
        threading.Thread(target=_do, daemon=True).start()
        self._start_auto_refresh()

    def _export_json(self):
        path = filedialog.asksaveasfilename(
            title="导出 JSON",
            defaultextension=".json",
            filetypes=[("JSON 文件", "*.json")],
            initialfile="kiro_accounts_export.json",
        )
        if not path:
            return
        try:
            count = export_to_json(self.conn, path)
            self._log(f"成功导出 {count} 个账号到 {Path(path).name}", "success")
        except Exception as e:
            self._log(f"导出失败: {e}", "error")

    def _delete_selected(self):
        sel = self.acc_tree.selection()
        if not sel:
            messagebox.showwarning("提示", "请先选择要删除的账号")
            return
        if not messagebox.askyesno("确认", f"确定删除选中的 {len(sel)} 个账号？"):
            return
        for iid in sel:
            db_delete(self.conn, int(iid))
        self._load_accounts_from_db()
        self._log(f"已删除 {len(sel)} 个账号", "warn")

    def _refresh_selected_token(self):
        sel = self.acc_tree.selection()
        if not sel:
            messagebox.showwarning("提示", "请先选择要刷新的账号")
            return
        if self.running:
            return
        self.running = True
        self._log(f"正在刷新 {len(sel)} 个账号的 Token...")

        def _do():
            success = 0
            for iid in sel:
                row_id = int(iid)
                row = self.conn.execute("SELECT * FROM accounts WHERE id=?", (row_id,)).fetchone()
                if not row:
                    continue
                at, rt, ea, err = do_refresh_token(row)
                if at:
                    db_update_token(self.conn, row_id, at, rt, ea)
                    _sync_subscription_after_refresh(self.conn, row, at)
                    # Re-read row to get updated subscription
                    updated = self.conn.execute("SELECT * FROM accounts WHERE id=?", (row_id,)).fetchone()
                    sub_display = format_subscription(updated["subscription"]) if updated else "-"
                    self.after(0, lambda i=iid, e=ea: self.acc_tree.set(i, "expires", e))
                    self.after(0, lambda i=iid: self.acc_tree.set(i, "status", "有效"))
                    self.after(0, lambda i=iid, s=sub_display: self.acc_tree.set(i, "subscription", s))
                    success += 1
                else:
                    self.after(0, lambda i=iid, e=err: self.acc_tree.set(i, "status", e))
                    self.after(0, lambda e=err, em=row["email"]:
                               self._log(f"{em}: {e}", "error"))
            self.after(0, lambda: self._log(f"Token 刷新完成: {success}/{len(sel)} 成功", "success"))
            self.running = False
        threading.Thread(target=_do, daemon=True).start()

    def _health_check(self):
        if self.running:
            return
        rows = db_get_all(self.conn)
        if not rows:
            messagebox.showinfo("提示", "数据库中无账号")
            return
        self.running = True
        self.acc_progress["value"] = 0
        self.acc_progress["maximum"] = len(rows)
        self._log("开始健康检查...")

        def _do():
            valid = 0
            expired_count = 0
            refreshed = 0
            failed = 0
            for i, row in enumerate(rows, 1):
                iid = str(row["id"])
                if not is_token_expired(row["expiresAt"]):
                    self.after(0, lambda i2=iid: self.acc_tree.set(i2, "status", "有效"))
                    valid += 1
                else:
                    at, rt, ea, err = do_refresh_token(row)
                    if at:
                        db_update_token(self.conn, row["id"], at, rt, ea)
                        _sync_subscription_after_refresh(self.conn, row, at)
                        updated = self.conn.execute("SELECT * FROM accounts WHERE id=?", (row["id"],)).fetchone()
                        sub_display = format_subscription(updated["subscription"]) if updated else "-"
                        self.after(0, lambda i2=iid, e=ea, s=sub_display: (
                            self.acc_tree.set(i2, "expires", e),
                            self.acc_tree.set(i2, "status", "已刷新"),
                            self.acc_tree.set(i2, "subscription", s),
                        ))
                        refreshed += 1
                    else:
                        self.after(0, lambda i2=iid: self.acc_tree.set(i2, "status", "无效"))
                        failed += 1
                        expired_count += 1
                self.after(0, lambda v=i: self.acc_progress.configure(value=v))

            msg = f"健康检查完成: 有效 {valid}, 已刷新 {refreshed}, 无效 {failed}"
            self.after(0, lambda: self._log(msg, "success" if failed == 0 else "warn"))
            self.running = False
        threading.Thread(target=_do, daemon=True).start()

    # ─── Models Panel ────────────────────────────────────────────────────
    def _toggle_models_panel(self):
        if self._models_visible.get():
            self.models_frame.pack_forget()
            self._models_visible.set(False)
            self.btn_models_toggle.configure(text="▶ 可用模型 (点击展开)")
        else:
            self.models_frame.pack(fill="both", expand=True, pady=(2, 0), before=self._log_label)
            self._models_visible.set(True)
            self.btn_models_toggle.configure(text="▼ 可用模型 (点击收起)")
            self._show_cached_models()

    def _on_acc_select(self, event):
        sel = self.acc_tree.selection()
        count = len(sel)
        if count > 0:
            self.lbl_sel_info.configure(text=f"已选中 {count} 个账号")
        else:
            self.lbl_sel_info.configure(text="")
        if self._models_visible.get():
            self._show_cached_models()

    def _on_acc_right_click(self, event):
        iid = self.acc_tree.identify_row(event.y)
        if not iid:
            return
        if iid not in self.acc_tree.selection():
            self.acc_tree.selection_set(iid)
        sel = self.acc_tree.selection()
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="复制账号 JSON", command=lambda: self._copy_account_json(iid))
        menu.add_command(label="复制邮箱", command=lambda: self._copy_field(iid, "email"))
        menu.add_command(label="复制密码", command=lambda: self._copy_field(iid, "password"))
        menu.add_command(label="复制 Access Token", command=lambda: self._copy_field(iid, "accessToken"))
        menu.add_separator()
        if len(sel) > 1:
            menu.add_command(label=f"复制选中 {len(sel)} 个账号 JSON", command=self._copy_selected_json)
            menu.add_command(label=f"复制选中 {len(sel)} 个邮箱", command=self._copy_selected_emails)
            menu.add_separator()
        menu.add_command(label="查看账号详情", command=lambda: self._show_account_detail(iid))
        menu.add_command(label="刷新此账号 Token", command=lambda: self._refresh_single_token(iid))
        menu.add_separator()
        menu.add_command(label="全选", command=self._select_all_accounts)
        menu.add_command(label="反选", command=self._invert_selection)
        menu.add_separator()
        menu.add_command(label="删除选中", command=self._delete_selected)
        menu.tk_popup(event.x_root, event.y_root)

    def _on_acc_double_click(self, event):
        iid = self.acc_tree.identify_row(event.y)
        if iid:
            self._show_account_detail(iid)

    def _show_account_detail(self, iid):
        row = self.conn.execute("SELECT * FROM accounts WHERE id=?", (int(iid),)).fetchone()
        if not row:
            return
        info_lines = [
            f"ID: {row['id']}",
            f"邮箱: {row['email'] or '(未知)'}",
            f"密码: {row['password'] or '(未保存)'}",
            f"登录方式: {row['provider'] or '-'}",
            f"认证类型: {row['authMethod'] or '-'}",
            f"订阅: {format_subscription(row['subscription'])}",
            f"超额状态: {row['overageStatus'] or '未开启'}",
            f"用量: {row['currentUsage']}/{row['usageLimit']}",
            f"Token过期: {row['expiresAt'] or '无'}",
            f"Region: {row['region'] or '-'}",
            f"创建时间: {row['createdAt'] or '-'}",
            f"更新时间: {row['updatedAt'] or '-'}",
        ]
        messagebox.showinfo("账号详情", "\n".join(info_lines))

    def _copy_field(self, iid, field):
        row = self.conn.execute("SELECT * FROM accounts WHERE id=?", (int(iid),)).fetchone()
        if row and row[field]:
            self.clipboard_clear()
            self.clipboard_append(row[field])
            self._log(f"已复制 {field} 到剪贴板", "success")

    def _account_to_json_dict(self, row):
        return {
            "email": row["email"],
            "password": row["password"] or "",
            "provider": row["provider"],
            "authMethod": row["authMethod"],
            "accessToken": row["accessToken"],
            "refreshToken": row["refreshToken"],
            "expiresAt": row["expiresAt"],
            "clientId": row["clientId"],
            "clientSecret": row["clientSecret"],
            "clientIdHash": row["clientIdHash"],
            "region": row["region"],
            "profileArn": row["profileArn"],
            "userId": row["userId"],
            "subscription": row["subscription"] or "",
            "usageData": {
                "usageBreakdownList": [{
                    "usageLimit": row["usageLimit"],
                    "currentUsage": row["currentUsage"],
                    "overageCap": row["overageCap"],
                    "currentOverages": row["currentOverages"],
                    "overageCharges": row["overageCharges"],
                }],
                "overageConfiguration": {
                    "overageStatus": row["overageStatus"] or "",
                },
            },
        }

    def _copy_account_json(self, iid):
        row = self.conn.execute("SELECT * FROM accounts WHERE id=?", (int(iid),)).fetchone()
        if not row:
            return
        data = self._account_to_json_dict(row)
        text = json.dumps(data, indent=2, ensure_ascii=False)
        self.clipboard_clear()
        self.clipboard_append(text)
        self._log(f"已复制 {row['email']} 的 JSON 到剪贴板", "success")

    def _copy_selected_json(self):
        sel = self.acc_tree.selection()
        if not sel:
            messagebox.showwarning("提示", "请先选择账号")
            return
        accounts = []
        for iid in sel:
            row = self.conn.execute("SELECT * FROM accounts WHERE id=?", (int(iid),)).fetchone()
            if row:
                accounts.append(self._account_to_json_dict(row))
        if not accounts:
            return
        text = json.dumps(accounts, indent=2, ensure_ascii=False)
        self.clipboard_clear()
        self.clipboard_append(text)
        self._log(f"已复制 {len(accounts)} 个账号 JSON 到剪贴板", "success")

    def _copy_selected_emails(self):
        sel = self.acc_tree.selection()
        if not sel:
            messagebox.showwarning("提示", "请先选择账号")
            return
        emails = []
        for iid in sel:
            row = self.conn.execute("SELECT email FROM accounts WHERE id=?", (int(iid),)).fetchone()
            if row and row["email"]:
                emails.append(row["email"])
        if emails:
            self.clipboard_clear()
            self.clipboard_append("\n".join(emails))
            self._log(f"已复制 {len(emails)} 个邮箱到剪贴板", "success")

    def _select_all_accounts(self):
        items = self.acc_tree.get_children()
        if items:
            self.acc_tree.selection_set(items)
            self.lbl_sel_info.configure(text=f"已选中 {len(items)} 个账号")

    def _invert_selection(self):
        all_items = set(self.acc_tree.get_children())
        selected = set(self.acc_tree.selection())
        new_sel = all_items - selected
        if new_sel:
            self.acc_tree.selection_set(list(new_sel))
        else:
            self.acc_tree.selection_remove(*all_items)
        count = len(new_sel)
        self.lbl_sel_info.configure(text=f"已选中 {count} 个账号" if count else "")

    def _refresh_single_token(self, iid):
        row_id = int(iid)
        row = self.conn.execute("SELECT * FROM accounts WHERE id=?", (row_id,)).fetchone()
        if not row:
            return
        self._log(f"正在刷新 {row['email']} 的 Token...")

        def _do():
            at, rt, ea, err = do_refresh_token(row)
            if at:
                db_update_token(self.conn, row_id, at, rt, ea)
                _sync_subscription_after_refresh(self.conn, row, at)
                updated = self.conn.execute("SELECT * FROM accounts WHERE id=?", (row_id,)).fetchone()
                sub_display = format_subscription(updated["subscription"]) if updated else "-"
                self.after(0, lambda: self.acc_tree.set(iid, "expires", ea))
                self.after(0, lambda: self.acc_tree.set(iid, "status", "有效"))
                self.after(0, lambda: self.acc_tree.set(iid, "subscription", sub_display))
                self.after(0, lambda: self._log(f"{row['email']} Token 刷新成功", "success"))
            else:
                self.after(0, lambda: self.acc_tree.set(iid, "status", err or "失败"))
                self.after(0, lambda: self._log(f"{row['email']}: {err}", "error"))
        threading.Thread(target=_do, daemon=True).start()

    def _refresh_all_tokens(self):
        rows = db_get_all(self.conn)
        targets = [r for r in rows if r["refreshToken"]]
        if not targets:
            messagebox.showinfo("提示", "没有可刷新的账号")
            return
        if self.running:
            return
        self.running = True
        self.acc_progress["value"] = 0
        self.acc_progress["maximum"] = len(targets)
        self._log(f"正在刷新全部 {len(targets)} 个账号的 Token...")

        def _do():
            from concurrent.futures import ThreadPoolExecutor, as_completed
            success = 0

            def _refresh_one(r):
                at, rt, ea, err = do_refresh_token(r)
                if at:
                    db_update_token(self.conn, r["id"], at, rt, ea)
                    _sync_subscription_after_refresh(self.conn, r, at)
                    return r, True, ea, None
                return r, False, None, err

            with ThreadPoolExecutor(max_workers=min(8, len(targets))) as pool:
                futures = {pool.submit(_refresh_one, r): r for r in targets}
                for i, fut in enumerate(as_completed(futures), 1):
                    r, ok, ea, err = fut.result()
                    iid = str(r["id"])
                    if ok:
                        updated = self.conn.execute("SELECT * FROM accounts WHERE id=?", (r["id"],)).fetchone()
                        sub_display = format_subscription(updated["subscription"]) if updated else "-"
                        self.after(0, lambda i2=iid, e=ea, s=sub_display: (
                            self.acc_tree.set(i2, "expires", e),
                            self.acc_tree.set(i2, "status", "有效"),
                            self.acc_tree.set(i2, "subscription", s),
                        ))
                        success += 1
                    else:
                        self.after(0, lambda i2=iid: self.acc_tree.set(i2, "status", "失败"))
                    self.after(0, lambda v=i: self.acc_progress.configure(value=v))

            self.after(0, lambda: self._log(
                f"全部刷新完成: {success}/{len(targets)} 成功",
                "success" if success == len(targets) else "warn"))
            self.running = False
        threading.Thread(target=_do, daemon=True).start()

    def _show_cached_models(self):
        sel = self.acc_tree.selection()
        self.models_text.delete("1.0", "end")
        if not sel:
            self.models_text.insert("end", "  请选择一个账号，然后点击「查询模型」\n", "dim")
            return
        row_id = int(sel[0])
        if row_id in self._models_cache:
            self._render_models(self._models_cache[row_id])
        else:
            self.models_text.insert("end", "  尚未查询，请点击「查询模型」按钮\n", "dim")

    def _query_selected_models(self):
        sel = self.acc_tree.selection()
        if not sel:
            messagebox.showwarning("提示", "请先选择一个账号")
            return
        row_id = int(sel[0])
        row = self.conn.execute("SELECT * FROM accounts WHERE id=?", (row_id,)).fetchone()
        if not row:
            return
        self._log(f"正在查询 {row['email']} 的可用模型...")
        if not self._models_visible.get():
            self._toggle_models_panel()

        def _do():
            access_token, err = get_valid_token(row, self.conn)
            if not access_token:
                self.after(0, lambda: self._log(f"Token 无效: {err}", "error"))
                return
            provider = row["provider"] or ""
            profile_arn = row["profileArn"] or FIXED_PROFILE_ARNS.get(provider, "")
            if not profile_arn:
                profile_arn = list_profiles(access_token) or ""
            if not profile_arn:
                self.after(0, lambda: self._log("无法获取 profileArn", "error"))
                return
            result = list_available_models(access_token, profile_arn)
            if result["ok"]:
                models_data = {
                    "models": result["models"],
                    "defaultModel": result["defaultModel"],
                }
                self._models_cache[row_id] = models_data
                self.after(0, lambda: self._render_models(models_data))
                self.after(0, lambda: self._log(
                    f"查询到 {len(result['models'])} 个可用模型", "success"))
            else:
                err_info = result.get("error", {})
                msg = err_info.get("message") or err_info.get("Message") or str(err_info)[:80]
                self.after(0, lambda: self._log(f"模型查询失败: {msg}", "error"))
                self.after(0, lambda: self.models_text.delete("1.0", "end"))
                self.after(0, lambda m=msg: self.models_text.insert("end", f"  查询失败: {m}\n", "dim"))
        threading.Thread(target=_do, daemon=True).start()

    def _render_models(self, models_data):
        self.models_text.delete("1.0", "end")
        default_model = models_data.get("defaultModel")
        models = models_data.get("models", [])

        if default_model:
            self.models_text.insert("end", "  默认模型: ", "title")
            name = default_model.get("modelName", default_model.get("modelId", ""))
            self.models_text.insert("end", f"{name}\n", "default")

        self.models_text.insert("end", f"\n  共 {len(models)} 个可用模型:\n", "title")
        self.models_text.insert("end", "  " + "─" * 70 + "\n", "dim")

        for m in models:
            name = m.get("modelName", "")
            mid = m.get("modelId", "")
            desc = m.get("description", "")
            rate = m.get("rateMultiplier")
            rate_unit = m.get("rateUnit", "")
            inputs = m.get("supportedInputTypes", [])

            is_default = default_model and mid == default_model.get("modelId")
            tag = "default" if is_default else "model"
            marker = " ★" if is_default else ""

            self.models_text.insert("end", f"  {name}{marker}\n", tag)
            self.models_text.insert("end", f"    ID: {mid}", "dim")
            if rate is not None:
                self.models_text.insert("end", f"  |  费率: {rate}x/{rate_unit}", "dim")
            if inputs:
                self.models_text.insert("end", f"  |  输入: {', '.join(inputs)}", "dim")
            self.models_text.insert("end", "\n", "dim")
            if desc:
                self.models_text.insert("end", f"    {desc}\n", "dim")

    # ─── Tab 2 Actions: 额度查询 ─────────────────────────────────────────
    def _query_all_usage(self):
        if self.running:
            return
        rows = db_get_all(self.conn)
        if not rows:
            messagebox.showinfo("提示", "数据库中无账号")
            return
        self.running = True
        self.usage_progress["value"] = 0
        self.usage_progress["maximum"] = len(rows)

        for item in self.usage_tree.get_children():
            self.usage_tree.delete(item)

        def _do():
            total_used = 0
            total_limit = 0
            total_overage = 0.0

            for i, row in enumerate(rows, 1):
                row_id = row["id"]
                email = row["email"] or ""
                provider = row["provider"] or ""

                access_token, err = get_valid_token(row, self.conn)
                if not access_token:
                    self.after(0, lambda rid=row_id, e=email, p=provider:
                        self.usage_tree.insert("", "end", iid=str(rid), values=(
                            rid, e, p, "-", "错误", "-", "-", "-", "-", "-"
                        )))
                    self.after(0, lambda v=i: self.usage_progress.configure(value=v))
                    continue

                profile_arn = row["profileArn"] or FIXED_PROFILE_ARNS.get(provider, "")
                if not profile_arn:
                    profile_arn = list_profiles(access_token) or ""

                if not profile_arn:
                    self.after(0, lambda rid=row_id, e=email, p=provider:
                        self.usage_tree.insert("", "end", iid=str(rid), values=(
                            rid, e, p, "-", "无ARN", "-", "-", "-", "-", "-"
                        )))
                    self.after(0, lambda v=i: self.usage_progress.configure(value=v))
                    continue

                result = query_usage(access_token, profile_arn)
                if result["ok"]:
                    data = result["data"]
                    bl = data.get("usageBreakdownList", [])
                    b = bl[0] if bl else {}
                    used = int(b.get("currentUsage", b.get("currentUsageWithPrecision", 0)))
                    limit = int(b.get("usageLimit", b.get("usageLimitWithPrecision", 0)))
                    ov_used = int(b.get("currentOverages", b.get("currentOveragesWithPrecision", 0)))
                    ov_cap = int(b.get("overageCap", b.get("overageCapWithPrecision", 0)))
                    ov_cost = float(b.get("overageCharges", 0))
                    ov_status = data.get("overageConfiguration", {}).get("overageStatus", "")
                    sub_info = data.get("subscriptionInfo", {})
                    sub_raw = sub_info.get("subscriptionTitle", "") or sub_info.get("type", "") if sub_info else ""

                    total_used += used
                    total_limit += limit
                    total_overage += ov_cost

                    db_update_usage(self.conn, row_id, {
                        "usageLimit": limit, "currentUsage": used,
                        "overageCap": ov_cap, "currentOverages": ov_used,
                        "overageStatus": ov_status, "overageCharges": ov_cost,
                        "subscription": sub_raw,
                    })

                    self.after(0, lambda rid=row_id, e=email, p=provider,
                               u=used, l=limit, ou=ov_used, oc=ov_cap,
                               ocost=ov_cost, os_=ov_status, sr=sub_raw:
                        self.usage_tree.insert("", "end", iid=str(rid), values=(
                            rid, e, p, format_subscription(sr), f"{u}/{l}", str(l),
                            str(ou), str(oc), f"${ocost:.2f}", os_ or "未开启"
                        )))
                else:
                    self.after(0, lambda rid=row_id, e=email, p=provider:
                        self.usage_tree.insert("", "end", iid=str(rid), values=(
                            rid, e, p, "-", "查询失败", "-", "-", "-", "-", "-"
                        )))

                self.after(0, lambda v=i: self.usage_progress.configure(value=v))

            self.after(0, lambda: self.lbl_usage_stats.configure(
                text=f"汇总: 已用 {total_used} | 总额度 {total_limit} | 超额费用 ${total_overage:.2f}"
            ))
            self.after(0, self._load_accounts_from_db)
            self.running = False
        threading.Thread(target=_do, daemon=True).start()

    def _query_selected_usage(self):
        sel = self.usage_tree.selection() or self.acc_tree.selection()
        if not sel:
            messagebox.showwarning("提示", "请先选择一个账号")
            return
        row_id = int(sel[0])
        row = self.conn.execute("SELECT * FROM accounts WHERE id=?", (row_id,)).fetchone()
        if not row:
            return

        self.usage_detail.delete("1.0", "end")
        access_token, err = get_valid_token(row, self.conn)
        if not access_token:
            self.usage_detail.insert("end", f"Token 获取失败: {err}\n", "warn")
            return

        profile_arn = row["profileArn"] or FIXED_PROFILE_ARNS.get(row["provider"] or "", "")
        if not profile_arn:
            profile_arn = list_profiles(access_token) or ""
        if not profile_arn:
            self.usage_detail.insert("end", "无法获取 profileArn\n", "warn")
            return

        result = query_usage(access_token, profile_arn)
        if result["ok"]:
            self._display_usage_detail(result["data"], row["email"] or "")
        else:
            err_data = result.get("error", {})
            msg = translate_api_error(err_data)
            self.usage_detail.insert("end", f"查询失败: {msg}\n", "warn")

    def _on_usage_select(self, event):
        sel = self.usage_tree.selection()
        if not sel:
            return
        row_id = int(sel[0])
        row = self.conn.execute("SELECT * FROM accounts WHERE id=?", (row_id,)).fetchone()
        if not row:
            return
        self.usage_detail.delete("1.0", "end")
        self.usage_detail.insert("end", "  账号: ", "key")
        self.usage_detail.insert("end", f"{row['email']}\n", "val")
        self.usage_detail.insert("end", "  登录方式: ", "key")
        self.usage_detail.insert("end", f"{row['provider']} / {row['authMethod']}\n", "val")
        self.usage_detail.insert("end", "  基础额度: ", "key")
        limit = row["usageLimit"] or 0
        used = row["currentUsage"] or 0
        pct = (used / limit * 100) if limit > 0 else 0
        tag = "ok" if pct < 80 else "warn"
        self.usage_detail.insert("end", f"{used}/{limit} ({pct:.1f}%)\n", tag)
        self.usage_detail.insert("end", "  超额已用: ", "key")
        self.usage_detail.insert("end", f"{row['currentOverages'] or 0}/{row['overageCap'] or 0}\n", "val")
        self.usage_detail.insert("end", "  超额费用: ", "key")
        self.usage_detail.insert("end", f"${row['overageCharges'] or 0:.2f}\n", "val")
        self.usage_detail.insert("end", "  超额状态: ", "key")
        self.usage_detail.insert("end", f"{row['overageStatus'] or '未开启'}\n", "val")
        self.usage_detail.insert("end", "  上次查询: ", "key")
        self.usage_detail.insert("end", f"{row['lastQueryTime'] or '从未'}\n", "val")

    def _display_usage_detail(self, data, email):
        self.usage_detail.delete("1.0", "end")
        self.usage_detail.insert("end", "  账号: ", "key")
        self.usage_detail.insert("end", f"{email}\n\n", "val")

        breakdown_list = data.get("usageBreakdownList", [])
        if not breakdown_list:
            self.usage_detail.insert("end", "  无用量数据\n", "warn")
            return

        for b in breakdown_list:
            display = b.get("displayName", b.get("resourceType", "UNKNOWN"))
            used = int(b.get("currentUsage", b.get("currentUsageWithPrecision", 0)))
            limit = int(b.get("usageLimit", b.get("usageLimitWithPrecision", 0)))
            ov_used = int(b.get("currentOverages", b.get("currentOveragesWithPrecision", 0)))
            ov_cap = int(b.get("overageCap", b.get("overageCapWithPrecision", 0)))
            ov_rate = b.get("overageRate", 0)
            ov_charges = b.get("overageCharges", 0)
            unit = b.get("unit", "")

            self.usage_detail.insert("end", f"  [{display}]\n", "key")
            pct = (used / limit * 100) if limit > 0 else 0
            tag = "ok" if pct < 80 else "warn"
            self.usage_detail.insert("end", f"    基础: {used}/{limit} ({pct:.1f}%)\n", tag)
            self.usage_detail.insert("end", f"    超额: {ov_used}/{ov_cap}  ", "val")
            self.usage_detail.insert("end", f"费率: ${ov_rate}/{unit.lower()}  ", "val")
            self.usage_detail.insert("end", f"费用: ${ov_charges:.2f}\n", "val")

    # ─── Tab 3 Actions: 批量操作 ─────────────────────────────────────────
    def _batch_enable_overage(self):
        if self.running:
            return
        rows = db_get_all(self.conn)
        if not rows:
            messagebox.showinfo("提示", "数据库中无账号")
            return
        self.running = True
        self.batch_progress["value"] = 0
        self.batch_progress["maximum"] = len(rows)

        for item in self.batch_tree.get_children():
            self.batch_tree.delete(item)

        self._blog(f"开始批量开启超额... (共 {len(rows)} 个账号)")

        def _do():
            success = 0
            skipped = 0
            failed = 0
            try:
                for i, row in enumerate(rows, 1):
                    if not self.running:
                        self.after(0, lambda: self._blog("批量操作已停止", "warn"))
                        break
                    row_id = row["id"]
                    email = row["email"] or ""
                    provider = row["provider"] or ""
                    self.after(0, lambda idx=i, total=len(rows), e=email:
                        self._blog(f"[{idx}/{total}] 处理: {e}", "info"))

                    if row["overageStatus"] == "ENABLED":
                        self.after(0, lambda rid=row_id, e=email, p=provider:
                            self.batch_tree.insert("", "end", iid=str(rid), values=(
                                rid, e, p, "开启超额", "已开启(跳过)"
                            )))
                        skipped += 1
                        self.after(0, lambda v=i: self.batch_progress.configure(value=v))
                        continue

                    # 跳过已知 Free 账号（仅根据本地已有字段判断，不发网络请求）
                    sub = (row["subscription"] or "")
                    sub_lower = sub.lower()
                    if sub_lower and ("free" in sub_lower and "pro" not in sub_lower and "power" not in sub_lower):
                        display = format_subscription(sub)
                        self.after(0, lambda rid=row_id, e=email, p=provider, d=display:
                            self.batch_tree.insert("", "end", iid=str(rid), values=(
                                rid, e, p, "开启超额", f"{d}不支持(跳过)"
                            )))
                        skipped += 1
                        self.after(0, lambda v=i: self.batch_progress.configure(value=v))
                        continue

                    access_token, err = get_valid_token(row, self.conn)
                    if not access_token:
                        self.after(0, lambda rid=row_id, e=email, p=provider, er=err:
                            self.batch_tree.insert("", "end", iid=str(rid), values=(
                                rid, e, p, "开启超额", f"Token错误: {er}"
                            )))
                        failed += 1
                        self.after(0, lambda v=i: self.batch_progress.configure(value=v))
                        continue

                    profile_arn = row["profileArn"] or FIXED_PROFILE_ARNS.get(provider, "")
                    if not profile_arn:
                        profile_arn = list_profiles(access_token) or ""
                    if not profile_arn:
                        self.after(0, lambda rid=row_id, e=email, p=provider:
                            self.batch_tree.insert("", "end", iid=str(rid), values=(
                                rid, e, p, "开启超额", "无法获取 ProfileArn"
                            )))
                        failed += 1
                        self.after(0, lambda v=i: self.batch_progress.configure(value=v))
                        continue

                    result = enable_overage(access_token, profile_arn)
                    if result["ok"]:
                        db_update_usage(self.conn, row_id, {
                            "usageLimit": row["usageLimit"], "currentUsage": row["currentUsage"],
                            "overageCap": row["overageCap"], "currentOverages": row["currentOverages"],
                            "overageStatus": "ENABLED", "overageCharges": row["overageCharges"],
                        })
                        self.after(0, lambda rid=row_id, e=email, p=provider:
                            self.batch_tree.insert("", "end", iid=str(rid), values=(
                                rid, e, p, "开启超额", "成功"
                            )))
                        success += 1
                    else:
                        err_data = result.get("error", {})
                        msg = translate_api_error(err_data)
                        # Free 账号 API 返回 FEATURE_NOT_SUPPORTED 时标记为跳过
                        if "不支持" in msg or "FEATURE_NOT_SUPPORTED" in str(err_data):
                            self.after(0, lambda rid=row_id, e=email, p=provider, m=msg:
                                self.batch_tree.insert("", "end", iid=str(rid), values=(
                                    rid, e, p, "开启超额", f"不支持(跳过): {m}"
                                )))
                            skipped += 1
                        else:
                            self.after(0, lambda rid=row_id, e=email, p=provider, m=msg:
                                self.batch_tree.insert("", "end", iid=str(rid), values=(
                                    rid, e, p, "开启超额", f"失败: {m}"
                                )))
                            failed += 1

                    self.after(0, lambda v=i: self.batch_progress.configure(value=v))

                msg = f"批量超额完成: 成功 {success}, 跳过 {skipped}, 失败 {failed}"
                self.after(0, lambda: self._blog(msg, "success" if failed == 0 else "warn"))
                self.after(0, lambda: self.lbl_batch_stats.configure(text=msg))
                self.after(0, self._load_accounts_from_db)
            except Exception as exc:
                self.after(0, lambda e=str(exc): self._blog(f"批量超额异常中断: {e}", "error"))
            finally:
                self.running = False
        threading.Thread(target=_do, daemon=True).start()

    def _inject_selected(self):
        sel = self.batch_tree.selection() or self.acc_tree.selection()
        if not sel:
            messagebox.showwarning("提示", "请先选择要注入的账号")
            return
        row_id = int(sel[0])
        row = self.conn.execute("SELECT * FROM accounts WHERE id=?", (row_id,)).fetchone()
        if not row:
            return

        # Refresh token first if needed
        access_token, err = get_valid_token(row, self.conn)
        if access_token:
            # Re-read row after potential token update
            row = self.conn.execute("SELECT * FROM accounts WHERE id=?", (row_id,)).fetchone()

        ok, msg = inject_account(row)
        if ok:
            self._blog(f"{row['email']} - {msg}", "success")
            self._refresh_local_status()
        else:
            self._blog(f"{row['email']} - {msg}", "error")

    # ─── Tab 4 Actions: 本地状态 ─────────────────────────────────────────
    def _refresh_local_status(self):
        self.status_text.delete("1.0", "end")
        token = get_local_token_status()
        if not token:
            self.status_text.insert("end", "未检测到本地 Kiro Token\n\n", "expired")
            self.status_text.insert("end", f"路径: {KIRO_CACHE_DIR / 'kiro-auth-token.json'}\n")
            self.status_text.insert("end", "\n请使用「注入」功能写入账号凭据")
            return

        fields = [
            ("认证方式", token.get("authMethod", "N/A")),
            ("登录方式", token.get("provider", "N/A")),
            ("区域", token.get("region", "N/A")),
            ("过期时间", token.get("expiresAt", "N/A")),
            ("ClientIdHash", token.get("clientIdHash", "N/A")),
            ("AccessToken", (token.get("accessToken", "")[:60] + "...") if token.get("accessToken") else "N/A"),
            ("RefreshToken", (token.get("refreshToken", "")[:60] + "...") if token.get("refreshToken") else "N/A"),
        ]

        for key, val in fields:
            self.status_text.insert("end", f"  {key:12s}: ", "key")
            self.status_text.insert("end", f"{val}\n", "val")

        self.status_text.insert("end", "\n")
        expires_at = token.get("expiresAt", "")
        if is_token_expired(expires_at):
            self.status_text.insert("end", "  状态: 已过期或即将过期\n", "expired")
            self.status_text.insert("end", "  Kiro 启动时会自动使用 RefreshToken 刷新\n", "val")
        else:
            try:
                for fmt in ("%Y-%m-%dT%H:%M:%S.000Z", "%Y-%m-%d %H:%M:%S"):
                    try:
                        expires = datetime.strptime(expires_at, fmt)
                        break
                    except ValueError:
                        continue
                remaining = int((expires - datetime.now()).total_seconds())
                mins = remaining // 60
                self.status_text.insert("end", f"  状态: 有效 (剩余 {mins} 分钟)\n", "ok")
            except Exception:
                self.status_text.insert("end", "  状态: 有效\n", "ok")

        client_hash = token.get("clientIdHash")
        if client_hash:
            client_path = KIRO_CACHE_DIR / f"{client_hash}.json"
            if client_path.exists():
                self.status_text.insert("end", f"\n  ClientReg: ", "key")
                self.status_text.insert("end", f"存在 ({client_path.name})\n", "ok")
            else:
                self.status_text.insert("end", f"\n  ClientReg: ", "key")
                self.status_text.insert("end", "缺失\n", "expired")

    def _refresh_local_token(self):
        token = get_local_token_status()
        if not token:
            messagebox.showwarning("提示", "本地无 Token，请先注入账号")
            return

        auth_method = token.get("authMethod", "")

        def _do():
            result = None
            if auth_method == "social":
                result = refresh_social_token(token.get("refreshToken", ""))
            elif auth_method == "IdC":
                client_hash = token.get("clientIdHash", "")
                client_path = KIRO_CACHE_DIR / f"{client_hash}.json"
                if not client_path.exists():
                    self.after(0, lambda: messagebox.showerror("错误", "缺少 clientRegistration 文件"))
                    return
                with open(client_path, "r", encoding="utf-8") as f:
                    client = json.load(f)
                region = token.get("region", "us-east-1")
                result = refresh_idc_token(
                    client["clientId"], client["clientSecret"],
                    token.get("refreshToken", ""), region
                )
            else:
                self.after(0, lambda: messagebox.showerror("错误", f"不支持的认证方式: {auth_method}"))
                return

            if result:
                token["accessToken"] = result["accessToken"]
                token["refreshToken"] = result["refreshToken"]
                token["expiresAt"] = (datetime.now() + timedelta(seconds=result["expiresIn"])).strftime("%Y-%m-%dT%H:%M:%S.000Z")
                save_data = {k: v for k, v in token.items() if k not in ("clientId", "clientSecret")}
                token_path = KIRO_CACHE_DIR / "kiro-auth-token.json"
                with open(token_path, "w", encoding="utf-8") as f:
                    json.dump(save_data, f, indent=2)
                self.after(0, self._refresh_local_status)
            else:
                self.after(0, lambda: messagebox.showerror("错误", "Token 刷新失败"))

        threading.Thread(target=_do, daemon=True).start()

    def _clear_local_token(self):
        if not messagebox.askyesno("确认", "确定要清除本地 Kiro Token 吗？\n清除后需要重新注入或登录。"):
            return
        token_path = KIRO_CACHE_DIR / "kiro-auth-token.json"
        if token_path.exists():
            token_path.unlink()
        self._refresh_local_status()


# ─── Entry Point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app = App()
    app.mainloop()