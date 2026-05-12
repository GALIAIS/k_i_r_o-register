"""
Kiro Pro 订阅模块 - 通过 API 获取 $0 试用 Pro 套餐的支付 URL

注册后首次获取的订阅支付 URL 是一次性的，关闭后无法再获得 $0 试用资格。
本模块通过 CodeWhisperer Runtime API 直接获取 Stripe 支付页面 URL。

API 流程:
1. POST /listAvailableSubscriptions → 获取可用套餐（含 subscriptionType）
2. POST /CreateSubscriptionToken → 获取一次性 Stripe 支付 URL (encodedVerificationUrl)

依赖: requests
"""
import json
import uuid
import requests
from datetime import datetime


CODEWHISPERER_ENDPOINT = "https://q.us-east-1.amazonaws.com"

FIXED_PROFILE_ARNS = {
    "BuilderId": "arn:aws:codewhisperer:us-east-1:638616132270:profile/AAAACCCCXXXX",
    "Github": "arn:aws:codewhisperer:us-east-1:699475941385:profile/EHGA3GRVQMUK",
    "Google": "arn:aws:codewhisperer:us-east-1:699475941385:profile/EHGA3GRVQMUK",
}


def _headers(access_token):
    return {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token}",
        "x-amz-target": "com.amazonaws.codewhisperer",
    }


def list_available_subscriptions(access_token, profile_arn, log=print):
    """
    获取可用订阅套餐列表。

    Returns:
        dict: {"ok": True, "data": {...}} 或 {"ok": False, "error": {...}}
    """
    url = f"{CODEWHISPERER_ENDPOINT}/listAvailableSubscriptions"
    payload = {"profileArn": profile_arn}

    log("查询可用订阅套餐...", "info")
    try:
        resp = requests.post(url, json=payload, headers=_headers(access_token),
                             timeout=30, verify=False)
        if resp.status_code == 200:
            data = resp.json()
            plans = data.get("subscriptionPlans", [])
            disclaimer = data.get("disclaimer", [])
            log(f"获取到 {len(plans)} 个套餐", "ok")
            for p in plans:
                title = p.get("description", {}).get("title", "Unknown")
                pricing = p.get("pricing", {})
                amount = pricing.get("amount", -1)
                currency = pricing.get("currency", "")
                sub_type = p.get("qSubscriptionType", "")
                log(f"  [{sub_type}] {title} - {amount} {currency}", "dbg")
            return {"ok": True, "data": data, "plans": plans, "disclaimer": disclaimer}
        else:
            error_body = resp.text[:500]
            log(f"查询套餐失败: HTTP {resp.status_code} - {error_body}", "error")
            return {"ok": False, "error": {"status": resp.status_code, "body": error_body}}
    except Exception as e:
        log(f"查询套餐异常: {e}", "error")
        return {"ok": False, "error": {"message": str(e)}}


def create_subscription_token(access_token, profile_arn, subscription_type,
                              success_url=None, cancel_url=None, log=print):
    """
    创建订阅 Token 并获取一次性 Stripe 支付 URL。

    Args:
        access_token: 有效的 accessToken
        profile_arn: profileArn
        subscription_type: 套餐类型（如 "KIRO_PRO"）
        success_url: 支付成功后跳转 URL（可选）
        cancel_url: 取消支付后跳转 URL（可选）

    Returns:
        dict: {"ok": True, "url": "...", "token": "...", "status": "..."} 或 {"ok": False, ...}
    """
    url = f"{CODEWHISPERER_ENDPOINT}/CreateSubscriptionToken"
    payload = {
        "provider": "STRIPE",
        "subscriptionType": subscription_type,
        "profileArn": profile_arn,
        "clientToken": str(uuid.uuid4()),
    }
    if success_url:
        payload["successUrl"] = success_url
    if cancel_url:
        payload["cancelUrl"] = cancel_url

    log(f"创建订阅 Token (type={subscription_type})...", "info")
    try:
        resp = requests.post(url, json=payload, headers=_headers(access_token),
                             timeout=30, verify=False)
        if resp.status_code == 200:
            data = resp.json()
            encoded_url = data.get("encodedVerificationUrl", "")
            status = data.get("status", "")
            token = data.get("token", "")
            if encoded_url:
                log(f"获取支付 URL 成功 (status={status})", "ok")
                log(f"[重要] 支付 URL (一次性): {encoded_url}", "warn")
            else:
                log(f"响应中无 encodedVerificationUrl, status={status}", "warn")
            return {
                "ok": True,
                "url": encoded_url,
                "token": token,
                "status": status,
                "raw": data,
            }
        else:
            error_body = resp.text[:500]
            log(f"创建订阅 Token 失败: HTTP {resp.status_code} - {error_body}", "error")
            return {"ok": False, "error": {"status": resp.status_code, "body": error_body}}
    except Exception as e:
        log(f"创建订阅 Token 异常: {e}", "error")
        return {"ok": False, "error": {"message": str(e)}}


def fetch_checkout_page(payment_url, log=print):
    """
    用 Playwright 打开 Stripe 支付页面，获取渲染后的元素并判断是否 $0 试用。

    Returns:
        dict: {is_free_trial, total_due_today, elements} 或 None
    """
    import asyncio

    async def _fetch():
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            log("playwright 未安装，跳过页面元素获取", "warn")
            return None

        log("获取支付页面元素...", "info")
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True, args=["--no-sandbox"])
                page = await browser.new_page(
                    viewport={"width": 1280, "height": 900}, locale="en-US"
                )
                await page.goto(payment_url, timeout=60000, wait_until="domcontentloaded")
                await asyncio.sleep(10)

                elements = await page.evaluate("""() => {
                    const result = {prices: [], headers: [], buttons: [], inputs: []};

                    document.querySelectorAll('*').forEach(el => {
                        const text = (el.innerText || el.textContent || '').trim();
                        if (text && text.length < 200 && el.children.length === 0) {
                            if (/\\$[\\d,.]+|free|trial|0\\.00|total|subtotal|per month|due today/i.test(text)) {
                                result.prices.push({tag: el.tagName, text: text});
                            }
                        }
                    });

                    document.querySelectorAll('h1, h2, h3, h4').forEach(el => {
                        const text = (el.innerText || '').trim();
                        if (text) result.headers.push({tag: el.tagName, text: text});
                    });

                    document.querySelectorAll('button, [role="button"], input[type="submit"]').forEach(btn => {
                        if (btn.offsetWidth > 0) {
                            result.buttons.push({
                                text: (btn.innerText || btn.value || '').trim().substring(0, 100),
                                disabled: btn.disabled || false,
                            });
                        }
                    });

                    document.querySelectorAll('input, select').forEach(inp => {
                        if (inp.offsetWidth > 0) {
                            result.inputs.push({
                                type: inp.type || '', name: inp.name || '',
                                placeholder: inp.placeholder || '',
                            });
                        }
                    });

                    return result;
                }""")

                await browser.close()

                # 判断是否 $0 试用: 从页面全文中提取 "due today" 金额
                import re
                all_price_text = " ".join(p["text"] for p in elements.get("prices", []))
                total_due = ""
                is_free = False

                # 方法1: 在价格元素中找 "due today" / "total" 相关文本
                for p in elements.get("prices", []):
                    txt = p["text"]
                    m = re.search(r'\$([\d,.]+)', txt)
                    if m and ("total" in txt.lower() or "due today" in txt.lower()):
                        total_due = f"${m.group(1)}"
                        if float(m.group(1).replace(",", "")) == 0:
                            is_free = True
                        break

                # 方法2: 找 "total"/"due today" 元素后紧跟的金额元素
                if not total_due:
                    prices = elements.get("prices", [])
                    for i, p in enumerate(prices):
                        txt = p["text"].lower()
                        if "total" in txt or "due today" in txt:
                            for pi in prices[i:]:
                                m = re.search(r'\$([\d,.]+)', pi["text"])
                                if m:
                                    total_due = f"${m.group(1)}"
                                    if float(m.group(1).replace(",", "")) == 0:
                                        is_free = True
                                    break
                            break

                # 方法3: fallback — 全文搜索 $0.00
                if not total_due:
                    if "$0.00" in all_price_text:
                        is_free = True
                        total_due = "$0.00"
                    else:
                        # 找到任意金额作为 total_due
                        m = re.search(r'\$([\d,.]+)', all_price_text)
                        if m:
                            total_due = f"${m.group(1)}"
                            if float(m.group(1).replace(",", "")) == 0:
                                is_free = True

                log(f"  页面标题: {elements['headers'][0]['text'] if elements['headers'] else 'N/A'}", "dbg")
                log(f"  价格信息: {[p['text'] for p in elements['prices']]}", "dbg")
                log(f"  今日应付: {total_due}", "info")
                log(f"  是否 $0 试用: {is_free}", "info")
                log(f"  输入框: {len(elements['inputs'])} 个", "dbg")
                log(f"  按钮: {[b['text'] for b in elements['buttons'] if b['text']]}", "dbg")

                return {
                    "is_free_trial": is_free,
                    "total_due_today": total_due,
                    "elements": elements,
                }
        except Exception as e:
            log(f"获取支付页面元素失败: {e}", "error")
            return None

    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                return pool.submit(lambda: asyncio.run(_fetch())).result(timeout=90)
        else:
            return asyncio.run(_fetch())
    except Exception:
        return asyncio.run(_fetch())


async def fetch_checkout_page_async(payment_url, log=print):
    """fetch_checkout_page 的 async 版本，可直接 await"""
    import asyncio
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        log("playwright 未安装，跳过页面元素获取", "warn")
        return None

    import re

    log("获取支付页面元素...", "info")
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True, args=["--no-sandbox"])
            page = await browser.new_page(
                viewport={"width": 1280, "height": 900}, locale="en-US"
            )
            await page.goto(payment_url, timeout=60000, wait_until="domcontentloaded")
            await asyncio.sleep(10)

            elements = await page.evaluate("""() => {
                const result = {prices: [], headers: [], buttons: [], inputs: []};
                document.querySelectorAll('*').forEach(el => {
                    const text = (el.innerText || el.textContent || '').trim();
                    if (text && text.length < 200 && el.children.length === 0) {
                        if (/\\$[\\d,.]+|free|trial|0\\.00|total|subtotal|per month|due today/i.test(text)) {
                            result.prices.push({tag: el.tagName, text: text});
                        }
                    }
                });
                document.querySelectorAll('h1, h2, h3, h4').forEach(el => {
                    const text = (el.innerText || '').trim();
                    if (text) result.headers.push({tag: el.tagName, text: text});
                });
                return result;
            }""")

            await browser.close()

            all_price_text = " ".join(item["text"] for item in elements.get("prices", []))
            total_due = ""
            is_free = False

            for item in elements.get("prices", []):
                txt = item["text"]
                m = re.search(r'\$([\d,.]+)', txt)
                if m and ("total" in txt.lower() or "due today" in txt.lower()):
                    total_due = f"${m.group(1)}"
                    if float(m.group(1).replace(",", "")) == 0:
                        is_free = True
                    break

            if not total_due:
                prices = elements.get("prices", [])
                for i, item in enumerate(prices):
                    txt = item["text"].lower()
                    if "total" in txt or "due today" in txt:
                        for pi in prices[i:]:
                            m = re.search(r'\$([\d,.]+)', pi["text"])
                            if m:
                                total_due = f"${m.group(1)}"
                                if float(m.group(1).replace(",", "")) == 0:
                                    is_free = True
                                break
                        break

            if not total_due:
                if "$0.00" in all_price_text:
                    is_free = True
                    total_due = "$0.00"
                else:
                    m = re.search(r'\$([\d,.]+)', all_price_text)
                    if m:
                        total_due = f"${m.group(1)}"
                        if float(m.group(1).replace(",", "")) == 0:
                            is_free = True

            log(f"  价格信息: {[item['text'] for item in elements['prices']]}", "dbg")
            log(f"  今日应付: {total_due}", "info")
            log(f"  是否 $0 试用: {is_free}", "info")

            return {
                "is_free_trial": is_free,
                "total_due_today": total_due,
                "elements": elements,
            }
    except Exception as e:
        log(f"获取支付页面元素失败: {e}", "error")
        return None

def subscribe_pro(access_token, profile_arn=None, provider="BuilderId",
                  subscription_type=None, log=print):
    """
    完整的 Pro 订阅流程：查询套餐 → 获取支付 URL。

    Args:
        access_token: 有效的 accessToken
        profile_arn: profileArn（为空时自动使用默认值）
        provider: 认证提供商（BuilderId/Github/Google）
        subscription_type: 指定套餐类型，为空时自动选择 Pro
        log: 日志回调

    Returns:
        dict with payment_url, plans, subscription_type, timestamp 或 None
    """
    if not profile_arn:
        profile_arn = FIXED_PROFILE_ARNS.get(provider, FIXED_PROFILE_ARNS["BuilderId"])

    log("=" * 50, "ok")
    log("开始 Pro 订阅流程", "info")
    log(f"  Provider: {provider}", "info")
    log(f"  ProfileArn: {profile_arn}", "info")
    log("=" * 50, "ok")

    # Step 1: 查询可用套餐
    plans_result = list_available_subscriptions(access_token, profile_arn, log)
    if not plans_result["ok"]:
        log("无法获取套餐列表，流程中止", "error")
        return None

    plans = plans_result["plans"]

    # Step 2: 选择 Pro 套餐
    if not subscription_type:
        # 自动选择包含 "PRO" 的套餐（排除 PRO_PLUS）
        for plan in plans:
            st = plan.get("qSubscriptionType", "")
            if "PRO" in st.upper() and "PLUS" not in st.upper() and "POWER" not in st.upper():
                subscription_type = st
                break
        if not subscription_type and plans:
            # 如果没找到 PRO，取第一个非 FREE 的
            for plan in plans:
                st = plan.get("qSubscriptionType", "")
                if "FREE" not in st.upper():
                    subscription_type = st
                    break

    if not subscription_type:
        log("未找到可用的 Pro 套餐", "error")
        return {"ok": False, "plans": plans, "error": "no_pro_plan"}

    log(f"选择套餐: {subscription_type}", "ok")

    # Step 3: 获取支付 URL
    token_result = create_subscription_token(
        access_token, profile_arn, subscription_type, log=log
    )
    if not token_result["ok"]:
        log("获取支付 URL 失败", "error")
        return {"ok": False, "plans": plans, "error": token_result.get("error")}

    payment_url = token_result["url"]

    # Step 4: 获取支付页面元素并判断是否 $0 试用
    page_info = fetch_checkout_page(payment_url, log=log)

    log("=" * 50, "ok")
    log("Pro 订阅流程完成", "ok")
    log(f"  套餐: {subscription_type}", "info")
    log(f"  支付 URL: {payment_url}", "warn")
    if page_info:
        log(f"  是否 $0 试用: {page_info.get('is_free_trial', 'unknown')}", "info")
        log(f"  今日应付: {page_info.get('total_due_today', 'unknown')}", "info")
    log("  [警告] 此 URL 为一次性链接，关闭后无法再获得 $0 试用", "warn")
    log("=" * 50, "ok")

    return {
        "ok": True,
        "payment_url": payment_url,
        "subscription_type": subscription_type,
        "token": token_result.get("token"),
        "status": token_result.get("status"),
        "is_free_trial": page_info.get("is_free_trial") if page_info else None,
        "total_due_today": page_info.get("total_due_today") if page_info else None,
        "page_elements": page_info.get("elements") if page_info else None,
        "plans": plans,
        "disclaimer": plans_result.get("disclaimer", []),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


# ─── 便捷入口：直接运行测试 ─────────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("用法: python kiro_subscribe.py <access_token> [profile_arn]")
        sys.exit(1)

    token = sys.argv[1]
    pa = sys.argv[2] if len(sys.argv) > 2 else None

    def _log(msg, level="info"):
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"[{ts}] [{level.upper():5s}] {msg}")

    result = subscribe_pro(token, profile_arn=pa, log=_log)
    if result and result.get("ok"):
        print("\n" + "=" * 60)
        print(f"支付 URL (一次性，务必保存): {result['payment_url']}")
        print("=" * 60)
        out_path = f"subscribe_result_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        print(f"完整结果已保存: {out_path}")
    else:
        print("订阅流程失败")
        if result:
            print(json.dumps(result, ensure_ascii=False, indent=2))
