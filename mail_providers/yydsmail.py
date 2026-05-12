"""YYDS Mail 临时邮箱服务"""
import hashlib
import random
import re
import string
import time
from datetime import datetime, timezone

from curl_cffi import requests as curl_requests

from .base import MailProvider


def _random_mailbox_name() -> str:
    return f"{''.join(random.choices(string.ascii_lowercase, k=5))}{''.join(random.choices(string.digits, k=random.randint(1, 3)))}{''.join(random.choices(string.ascii_lowercase, k=random.randint(1, 3)))}"


def _parse_received_at(value) -> datetime | None:
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except Exception:
            return None
    text = str(value or "").strip()
    if not text:
        return None
    try:
        date = datetime.fromisoformat(text[:-1] + "+00:00" if text.endswith("Z") else text)
        return date if date.tzinfo else date.replace(tzinfo=timezone.utc)
    except Exception:
        pass
    return None


def _extract_code(message: dict) -> str | None:
    content = f"{message.get('subject', '')}\n{message.get('text_content', '')}\n{message.get('html_content', '')}".strip()
    if not content:
        return None
    match = re.search(r"background-color:\s*#F3F3F3[^>]*>[\s\S]*?(\d{6})[\s\S]*?</p>", content, re.I)
    if match:
        return match.group(1)
    match = re.search(r"(?:Verification code|code is|代码为|验证码)[:\s]*(\d{6})", content, re.I)
    if match and match.group(1) != "177010":
        return match.group(1)
    for code in re.findall(r">\s*(\d{6})\s*<|(?<![#&])\b(\d{6})\b", content):
        value = code[0] or code[1]
        if value and value != "177010":
            return value
    return None


class YydsMailProvider(MailProvider):
    """YYDS Mail 临时邮箱服务提供者"""

    name = "yydsmail"
    display_name = "YYDS Mail"

    def __init__(self, api_key: str = "", base_url: str = "", domain: str = "", subdomain: str = "", wildcard: bool = False):
        self.api_base = str(base_url or "https://maliapi.215.im/v1").rstrip("/")
        self.api_key = str(api_key).strip()
        self.domain = str(domain).strip()
        self.subdomain = str(subdomain).strip()
        self.wildcard = bool(wildcard)
        self.session = curl_requests.Session(impersonate="chrome131")
        self.session.headers.update({
            "Accept": "application/json",
            "Content-Type": "application/json",
        })
        self.token = None
        self.address = None
        self.account_id = None

    def _request(self, method: str, path: str, token: str = "", params: dict | None = None, payload: dict | None = None, expected: tuple[int, ...] = (200, 201, 204)):
        headers = {"Authorization": f"Bearer {token}"} if token else {"X-API-Key": self.api_key}
        resp = self.session.request(
            method.upper(),
            f"{self.api_base}{path}",
            headers=headers,
            params=params,
            json=payload,
            timeout=30,
            verify=False,
        )
        if resp.status_code not in expected:
            raise RuntimeError(f"YYDSMail 请求失败: {method} {path}, HTTP {resp.status_code}, body={resp.text[:300]}")
        if resp.status_code == 204:
            return {}
        data = resp.json()
        if isinstance(data, dict) and data.get("success") is False:
            raise RuntimeError(f"YYDSMail 请求失败: {data.get('errorCode') or data.get('error')}")
        return data.get("data") if isinstance(data, dict) and isinstance(data.get("data"), (dict, list)) else data

    @staticmethod
    def _items(data):
        return data if isinstance(data, list) else data.get("items") or data.get("messages") or data.get("data") or []

    def create_mailbox(self) -> str:
        payload = {"localPart": _random_mailbox_name()}
        if self.domain:
            payload["domain"] = self.domain
        if self.subdomain:
            payload["subdomain"] = self.subdomain
        data = self._request("POST", "/accounts/wildcard" if self.wildcard else "/accounts", payload=payload)
        self.address = str(data.get("address") or data.get("email") or "").strip()
        self.token = str(data.get("token") or data.get("temp_token") or data.get("tempToken") or data.get("access_token") or "").strip()
        self.account_id = str(data.get("id") or "")
        if not self.address or not self.token:
            raise RuntimeError("YYDSMail 缺少 address 或 token")
        return self.address

    def wait_otp(self, timeout: int = 120, poll_interval: int = 3) -> str:
        if not self.token or not self.address:
            return ""

        seen_refs = set()

        def extract_unseen_code(message: dict) -> str | None:
            content = f"{message.get('subject', '')}\n{message.get('text_content', '')}\n{message.get('html_content', '')}".strip()
            received_at = message.get("received_at")
            received_value = received_at.isoformat() if isinstance(received_at, datetime) else str(received_at or "")
            digest = hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()
            ref = f"content:yydsmail:{self.address}:{received_value}:{digest}"

            if ref in seen_refs:
                return None
            code = _extract_code(message)
            if code:
                seen_refs.add(ref)
            return code

        deadline = time.time() + timeout
        while time.time() < deadline:
            message = self._fetch_latest_message()
            if message:
                code = extract_unseen_code(message)
                if code:
                    return code
            time.sleep(max(0.2, poll_interval))
        return ""

    def _fetch_latest_message(self) -> dict | None:
        data = self._request(
            "GET", "/messages",
            token=str(self.token or ""),
            params={"address": self.address}
        )
        messages = [item for item in self._items(data) if isinstance(item, dict)]
        if not messages:
            return None
        item = max(messages, key=lambda value: (
            (_parse_received_at(value.get("createdAt") or value.get("created_at") or value.get("receivedAt") or value.get("date") or value.get("timestamp")) or datetime.fromtimestamp(0, tz=timezone.utc)).timestamp(),
            str(value.get("id") or "")
        ))
        message_id = str(item.get("id") or item.get("message_id") or "").strip()
        if message_id:
            item = self._request("GET", f"/messages/{message_id}", token=str(self.token or ""), params={"address": self.address})

        text_content = str(item.get("text_content") or item.get("text") or item.get("body") or item.get("content") or "")
        html_content = str(item.get("html_content") or item.get("html") or item.get("html_body") or item.get("body_html") or "")
        sender = item.get("from") or item.get("sender") or ""
        if isinstance(sender, dict):
            sender = sender.get("address") or sender.get("email") or sender.get("name") or ""

        return {
            "provider": self.name,
            "mailbox": self.address,
            "message_id": message_id,
            "subject": str(item.get("subject") or ""),
            "sender": str(sender),
            "text_content": text_content,
            "html_content": html_content,
            "received_at": _parse_received_at(item.get("createdAt") or item.get("created_at") or item.get("receivedAt") or item.get("date") or item.get("timestamp")),
            "raw": item,
        }

    def list_domains(self) -> list[dict]:
        try:
            data = self._request("GET", "/domains", token=str(self.token or ""))
            items = self._items(data)
            domains = []
            for item in items:
                if isinstance(item, dict):
                    domain_id = str(item.get("id") or item.get("domain_id") or "")
                    domain_name = str(item.get("domain") or item.get("name") or "")
                    if domain_id and domain_name:
                        domains.append({"id": domain_id, "domain": domain_name})
            return domains
        except Exception:
            return [{"id": "default", "domain": "(API 默认)"}]

    def close(self) -> None:
        self.session.close()