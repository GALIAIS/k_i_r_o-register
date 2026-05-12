"""
Stripe Checkout 自动支付模块
- 兑换 EFunCard 虚拟信用卡
- 填入 Stripe Checkout 表单
- 处理 hCaptcha (invisible) 和 3DS 验证
"""
import asyncio
import json
import os
import random
import time
import requests
import urllib3
urllib3.disable_warnings()
from datetime import datetime
from playwright.async_api import async_playwright
from captcha_solver import solve_hcaptcha

EFUNCARD_API = "https://card.efuncard.com/api/external"
EFUNCARD_TOKEN = "b352d13f20462ed46cff0aa417065496bd811eb8396b2e2fee11aeacb796fc00"


def log(msg, level='info'):
    ts = datetime.now().strftime('%H:%M:%S')
    print(f'[{ts}] [{level.upper():5s}] {msg}')


def efun_redeem(code, log=log):
    """兑换 CDK 获取虚拟信用卡信息"""
    try:
        resp = requests.post(
            f"{EFUNCARD_API}/redeem",
            headers={
                "Authorization": f"Bearer {EFUNCARD_TOKEN}",
                "Content-Type": "application/json",
            },
            json={"code": code},
            timeout=(10, 90),
            verify=False,
        )
        data = resp.json()
        if data.get("success"):
            card = data["data"]
            log(f"卡片兑换成功: *{card['lastFour']} ({card['status']})", "ok")
            log(f"  有效期至: {card.get('autoCancelAt', 'N/A')}", "info")
            return card
        else:
            log(f"兑换响应: {data.get('error')}", "warn")
            return None
    except Exception as e:
        log(f"兑换请求异常: {e}", "warn")
        return None


def efun_query(code, log=log):
    """查询已兑换卡片信息"""
    try:
        resp = requests.get(
            f"{EFUNCARD_API}/cards/query/{code}",
            headers={
                "Authorization": f"Bearer {EFUNCARD_TOKEN}",
                "Content-Type": "application/json",
            },
            timeout=30,
            verify=False,
        )
        data = resp.json()
        if data.get("success"):
            return data["data"]
        log(f"查询响应: {data.get('error')}", "warn")
        return None
    except Exception as e:
        log(f"查询请求异常: {e}", "warn")
        return None


def efun_3ds_verify(code, minutes=5, log=log):
    """查询 3DS 验证码"""
    try:
        resp = requests.post(
            f"{EFUNCARD_API}/3ds/verify",
            headers={
                "Authorization": f"Bearer {EFUNCARD_TOKEN}",
                "Content-Type": "application/json",
            },
            json={"code": code, "minutes": minutes},
            timeout=30,
            verify=False,
        )
        if resp.status_code != 200 or not resp.text.strip():
            log(f"3DS API 响应异常: HTTP {resp.status_code}, body='{resp.text[:100]}'", "warn")
            return None
        try:
            data = resp.json()
        except (ValueError, requests.exceptions.JSONDecodeError):
            log(f"3DS API 返回非 JSON: '{resp.text[:100]}'", "warn")
            return None
        if data.get("success"):
            verifications = data["data"].get("verifications", [])
            if verifications:
                latest = verifications[0]
                log(f"3DS 验证码: {latest['otp']} (merchant: {latest.get('merchant', 'N/A')})", "ok")
                return latest
            log("暂无 3DS 验证码", "info")
            return None
        log(f"3DS 查询失败: {data.get('error')}", "error")
        return None
    except Exception as e:
        log(f"3DS 查询异常: {e}", "warn")
        return None


async def fill_stripe_checkout(payment_url, card_info, cdk_code, log=log, headless=True):
    """
    自动填写 Stripe Checkout 表单并提交（无头模式）
    """
    card_number = card_info["cardNumber"]
    cvv = card_info["cvv"]
    expiry_month = str(card_info["expiryMonth"]).zfill(2)
    expiry_year = str(card_info["expiryYear"])[-2:]
    name_on_card = card_info.get("nameOnCard", "Amy Allen")
    billing_address = card_info.get("billingAddress", "") or card_info.get("nodeInstructions", "")

    addr_parts = [p.strip() for p in billing_address.split(",")]
    address_line1 = addr_parts[0] if len(addr_parts) > 0 else ""
    city = addr_parts[1] if len(addr_parts) > 1 else ""
    state = addr_parts[2] if len(addr_parts) > 2 else ""
    postal_code = addr_parts[3] if len(addr_parts) > 3 else ""
    country = addr_parts[4] if len(addr_parts) > 4 else "US"

    log(f"卡号: *{card_number[-4:]}, 有效期: {expiry_month}/{expiry_year}, 姓名: {name_on_card}")
    log(f"地址: {address_line1}, {city}, {state} {postal_code}, {country}")

    browser = None
    try:
        async with async_playwright() as p:
            from playwright_stealth import Stealth
            from kiro_register import _random_fingerprint_config, _build_fingerprint_script

            fp = _random_fingerprint_config()
            launch_args = [
                "--disable-blink-features=AutomationControlled",
                "--disable-features=IsolateOrigins,site-per-process",
                "--no-first-run",
                f"--window-size={fp['screen']['width']},{fp['screen']['height']}",
            ]
            if headless:
                launch_args += ["--no-sandbox", "--disable-gpu"]

            browser = await p.chromium.launch(
                headless=headless,
                args=launch_args,
            )
            context = await browser.new_context(
                viewport=fp["viewport"],
                screen=fp["screen"],
                locale=fp["locale"],
                timezone_id=fp["timezone"],
                user_agent=fp["user_agent"],
                color_scheme="light",
                device_scale_factor=fp["pixel_ratio"],
            )
            page = await context.new_page()
            await Stealth().apply_stealth_async(page)
            await context.add_init_script(_build_fingerprint_script(fp))

            log("加载 Stripe 支付页面...")
            try:
                await page.goto(payment_url, timeout=60000, wait_until="domcontentloaded")
            except Exception:
                log("页面加载失败，重试...", "warn")
                await asyncio.sleep(3)
                try:
                    await page.goto(payment_url, timeout=60000, wait_until="commit")
                except Exception:
                    log("支付页面无法加载", "error")
                    return {"ok": False, "status": "error", "message": "页面加载失败"}

            # 等待表单元素出现
            try:
                await page.wait_for_selector("#cardNumber", timeout=30000)
            except Exception:
                log("支付表单未加载，可能链接已失效", "error")
                return {"ok": False, "status": "error", "message": "支付表单未出现"}

            await asyncio.sleep(2)

            # 检查页面金额，非 $0 试用则中止
            log("检测试用状态: 读取今日应付金额...", "info")
            amount_value = None
            try:
                amount_text = await page.evaluate(r"""() => {
                    const body = document.body.innerText;
                    // 找 "Total due today" 或 "due today" 后面紧跟的金额(下一行)
                    const m = body.match(/(?:total due today|due today|amount due)\s*\n\s*\$([\d,.]+)/i);
                    if (m) return m[1];
                    // 找 "total" 后面紧跟的金额
                    const m2 = body.match(/\btotal\b\s*\n\s*\$([\d,.]+)/i);
                    if (m2) return m2[1];
                    return '';
                }""")
                if amount_text:
                    amount_value = float(amount_text.replace(",", ""))
                    log(f"页面金额: ${amount_text} (今日应付)", "info")
                    if amount_value > 0:
                        log(f"非 $0 试用 (${amount_text})，中止支付", "error")
                        await browser.close()
                        return {"ok": False, "status": "not_free_trial",
                                "message": f"今日应付 ${amount_text}，非免费试用"}
                    else:
                        log("今日应付 $0.00，确认为免费试用", "info")
                else:
                    log("未检测到 Total due today 金额，继续...", "warn")
            except Exception as e:
                log(f"金额检测异常: {e}", "warn")

            # 选择国家
            log("设置国家: United States")
            try:
                country_sel = page.locator("#billingCountry")
                if await country_sel.count() > 0:
                    await country_sel.select_option("US")
                    await asyncio.sleep(random.uniform(0.8, 1.5))
            except Exception:
                pass

            async def _stripe_move(loc):
                try:
                    box = await loc.bounding_box()
                    if box:
                        x = box["x"] + box["width"] * random.uniform(0.3, 0.7)
                        y = box["y"] + box["height"] * random.uniform(0.3, 0.7)
                        await page.mouse.move(x, y, steps=random.randint(5, 12))
                        await asyncio.sleep(random.uniform(0.1, 0.3))
                except Exception:
                    pass

            async def _stripe_type(loc, text, delay_range=(40, 110)):
                await _stripe_move(loc)
                await loc.click()
                await asyncio.sleep(random.uniform(0.2, 0.5))
                await loc.fill("")
                for i, ch in enumerate(text):
                    await page.keyboard.type(ch, delay=0)
                    d = random.uniform(delay_range[0], delay_range[1]) / 1000
                    if random.random() < 0.06:
                        d += random.uniform(0.15, 0.4)
                    await asyncio.sleep(d)
                await asyncio.sleep(random.uniform(0.4, 0.9))

            # 填写卡号
            log("填写卡号...")
            card_input = page.locator("#cardNumber")
            await _stripe_type(card_input, card_number, (45, 100))

            # 填写有效期
            log("填写有效期...")
            expiry_input = page.locator("#cardExpiry")
            await _stripe_type(expiry_input, f"{expiry_month}{expiry_year}", (50, 120))

            # 填写 CVV
            log("填写 CVV...")
            cvc_input = page.locator("#cardCvc")
            await _stripe_type(cvc_input, cvv, (60, 140))

            # 填写持卡人姓名
            log("填写持卡人姓名...")
            name_input = page.locator("#billingName")
            await _stripe_type(name_input, name_on_card, (35, 90))

            # 填写地址
            log("填写账单地址...")
            try:
                addr_input = page.locator("#billingAddressLine1")
                await _stripe_type(addr_input, address_line1, (30, 80))
            except Exception:
                pass

            try:
                postal_input = page.locator("#billingPostalCode")
                if await postal_input.count() > 0 and await postal_input.is_visible():
                    await _stripe_type(postal_input, postal_code, (50, 120))
            except Exception:
                pass

            try:
                city_input = page.locator("#billingLocality")
                if await city_input.count() > 0 and await city_input.is_visible():
                    await _stripe_type(city_input, city, (35, 90))
            except Exception:
                pass

            try:
                state_select = page.locator("#billingAdministrativeArea")
                if await state_select.count() > 0 and await state_select.is_visible():
                    try:
                        await state_select.select_option(state.strip())
                    except Exception:
                        try:
                            await state_select.fill(state.strip())
                        except Exception:
                            pass
                    await asyncio.sleep(0.2)
            except Exception:
                pass

            log("表单填写完成，准备提交...", "ok")
            await asyncio.sleep(random.uniform(1.5, 3.0))

            # 点击 Subscribe 按钮
            log("点击 Subscribe...")
            submit_btn = page.locator('button[type="submit"]')
            if await submit_btn.count() > 0:
                await _stripe_move(submit_btn)
                await asyncio.sleep(random.uniform(0.3, 0.8))
                await submit_btn.click()
            else:
                log("未找到提交按钮", "error")
                return {"ok": False, "status": "error", "message": "未找到提交按钮"}

            # 等待结果
            log("等待支付处理...")
            result = await _wait_for_payment_result(page, cdk_code, log)

            await browser.close()
            browser = None
            return result

    except Exception as e:
        err_msg = str(e)
        if "Target" in err_msg and "closed" in err_msg:
            log("浏览器意外关闭，支付中断", "error")
        elif "Timeout" in err_msg:
            log("操作超时", "error")
        else:
            log(f"支付流程异常: {err_msg[:100]}", "error")
        return {"ok": False, "status": "error", "message": err_msg[:100]}
    finally:
        if browser:
            try:
                await browser.close()
            except Exception:
                pass


async def _wait_for_payment_result(page, cdk_code, log, timeout=120):
    """等待支付结果，处理 hCaptcha 和 3DS"""
    start = time.time()

    while time.time() - start < timeout:
        await asyncio.sleep(3)

        try:
            # 检查页面是否还活着
            current_url = page.url
        except Exception:
            log("页面已关闭", "error")
            return {"ok": False, "status": "error", "message": "页面意外关闭"}

        if "success" in current_url or "return_url" in current_url:
            log("支付成功! 页面已跳转", "ok")
            return {"ok": True, "status": "success", "url": current_url}

        try:
            page_text = await page.evaluate("() => document.body.innerText")
        except Exception:
            page_text = ""

        if "thank you" in page_text.lower() or "subscription active" in page_text.lower():
            log("支付成功! 检测到确认信息", "ok")
            return {"ok": True, "status": "success", "message": "subscription confirmed"}

        # hCaptcha 检测
        try:
            hcaptcha_visible = await page.evaluate("""() => {
                const iframe = document.querySelector('iframe[src*="hcaptcha.com/captcha"]');
                if (iframe && iframe.offsetWidth > 50 && iframe.offsetHeight > 50) return true;
                const challenge = document.querySelector('[data-hcaptcha-widget-id]');
                if (challenge && challenge.offsetWidth > 50) return true;
                return false;
            }""")
        except Exception:
            continue

        if hcaptcha_visible:
            log("检测到 hCaptcha，启动 YesCaptcha 求解...", "warn")
            try:
                solved = await solve_hcaptcha(page, log_fn=log)
                if solved:
                    log("hCaptcha 求解成功!", "ok")
                else:
                    log("hCaptcha 求解失败", "error")
                    return {"ok": False, "status": "error", "message": "hCaptcha 求解失败"}
            except Exception:
                log("hCaptcha 处理异常", "error")
            continue

        # 3DS 检测
        try:
            is_3ds = await page.evaluate("""() => {
                const iframes = Array.from(document.querySelectorAll('iframe'));
                for (const f of iframes) {
                    if (f.src && (f.src.includes('3ds') || f.src.includes('acs') ||
                        f.src.includes('authenticate') || f.src.includes('challenge'))) {
                        return f.offsetWidth > 50;
                    }
                }
                const overlay = document.querySelector('[class*="3ds"], [class*="challenge"], [id*="3ds"]');
                return overlay && overlay.offsetWidth > 50;
            }""")
        except Exception:
            continue

        if is_3ds:
            log("检测到 3DS 验证!", "warn")
            try:
                await _handle_3ds(page, cdk_code, log)
            except Exception:
                log("3DS 处理异常", "error")
            continue

        # 错误信息检测
        try:
            error_msg = await page.evaluate("""() => {
                const err = document.querySelector('[class*="error"], [class*="Error"], [role="alert"]');
                return err ? err.innerText.trim() : '';
            }""")
            if error_msg and len(error_msg) > 5:
                log(f"支付错误: {error_msg}", "error")
                return {"ok": False, "status": "error", "message": error_msg}
        except Exception:
            pass

        # 按钮状态
        try:
            btn_text = await page.evaluate("""() => {
                const btn = document.querySelector('button[type="submit"]');
                return btn ? btn.innerText.trim() : '';
            }""")
            if "processing" in btn_text.lower():
                log("处理中...", "dbg")
        except Exception:
            pass

    log("支付超时", "error")
    return {"ok": False, "status": "timeout"}


async def _handle_3ds(page, cdk_code, log):
    """处理 3DS 验证 - 从 EFunCard API 获取验证码并填入"""
    log("正在获取 3DS 验证码...", "info")

    # 轮询获取 3DS 验证码
    for attempt in range(10):
        await asyncio.sleep(5)
        verification = efun_3ds_verify(cdk_code, minutes=5, log=log)
        if verification:
            otp = verification["otp"]
            log(f"获取到 3DS OTP: {otp}", "ok")

            # 尝试在 3DS iframe 中填入验证码
            frames = page.frames
            for frame in frames:
                if frame == page.main_frame:
                    continue
                try:
                    otp_input = frame.locator('input[type="text"], input[type="tel"], input[name*="otp"], input[name*="code"], input[placeholder*="code"]')
                    if await otp_input.count() > 0:
                        await otp_input.first.fill(otp)
                        log("3DS 验证码已填入", "ok")
                        await asyncio.sleep(1)

                        # 点击提交按钮
                        submit = frame.locator('button[type="submit"], input[type="submit"], button:has-text("Submit"), button:has-text("Verify")')
                        if await submit.count() > 0:
                            await submit.first.click()
                            log("3DS 验证已提交", "ok")
                        return
                except Exception:
                    continue

            # 如果没找到 iframe 内的输入框，尝试主页面
            try:
                otp_input = page.locator('input[name*="otp"], input[name*="code"], input[autocomplete*="one-time"]')
                if await otp_input.count() > 0:
                    await otp_input.first.fill(otp)
                    submit = page.locator('button[type="submit"]')
                    if await submit.count() > 0:
                        await submit.first.click()
                    log("3DS 验证码已在主页面填入并提交", "ok")
                    return
            except Exception:
                pass

            log("未找到 3DS 输入框，等待手动处理...", "warn")
            return

    log("3DS 验证码获取超时", "error")


async def auto_pay(payment_url, cdk_code, gemini_key=None, captcha_config=None, headless=True, log=log):
    """
    完整自动支付流程:
    1. 兑换/查询虚拟信用卡
    2. 填写 Stripe 表单
    3. 处理验证并提交 (hCaptcha + 3DS)

    captcha_config: dict with keys: yescaptcha_key (推荐)
    """
    if captcha_config:
        if captcha_config.get("yescaptcha_key"):
            os.environ["YESCAPTCHA_API_KEY"] = captcha_config["yescaptcha_key"]
        if captcha_config.get("api_key"):
            os.environ["CAPTCHA_API_KEY"] = captcha_config["api_key"]
    elif gemini_key:
        os.environ["CAPTCHA_API_KEY"] = gemini_key

    log("=" * 50, "ok")
    log("开始自动支付流程", "info")
    log("=" * 50, "ok")

    # Step 1: 获取卡片信息
    # 先查询是否已兑换且激活，避免重复兑换
    log("查询虚拟信用卡状态...")
    card_info = efun_query(cdk_code, log)

    if card_info and card_info.get("cardNumber") and card_info.get("status") == "ACTIVE":
        log(f"卡片已激活可用: *{card_info.get('lastFour', '????')}", "ok")
    else:
        # 未兑换或未激活，尝试兑换
        log("卡片未就绪，尝试兑换...")
        card_info = None
        for retry in range(3):
            card_info = efun_redeem(cdk_code, log)
            if card_info and card_info.get("cardNumber"):
                break
            if retry < 2:
                log(f"兑换未返回卡信息，等待 10s 后查询...", "info")
                time.sleep(10)
                card_info = efun_query(cdk_code, log)
                if card_info and card_info.get("cardNumber"):
                    break

        # 轮询等待卡片就绪
        if not card_info or not card_info.get("cardNumber"):
            log("轮询等待开卡...", "info")
            for attempt in range(18):
                time.sleep(10)
                log(f"查询卡片... ({(attempt+1)*10}s)", "info")
                card_info = efun_query(cdk_code, log)
                if card_info and card_info.get("cardNumber"):
                    break
            if not card_info or not card_info.get("cardNumber"):
                log("开卡超时，无法获取卡片信息!", "error")
                return None

        # 等待激活
        if card_info.get("status") and card_info["status"] != "ACTIVE":
            log(f"卡片状态: {card_info['status']}，等待激活...", "info")
            for attempt in range(12):
                time.sleep(5)
                card_info = efun_query(cdk_code, log)
                if card_info and card_info.get("status") == "ACTIVE":
                    log("卡片已激活!", "ok")
                    break
            else:
                if not card_info or card_info.get("status") != "ACTIVE":
                    log(f"卡片未能激活: {card_info.get('status') if card_info else 'None'}", "error")
                    return None

    # Step 2: 填写并提交
    result = await fill_stripe_checkout(payment_url, card_info, cdk_code, log, headless=headless)

    log("=" * 50, "ok")
    if result and result.get("ok"):
        log("支付流程完成!", "ok")
    else:
        log(f"支付流程结束: {result}", "warn")
    log("=" * 50, "ok")

    return result


if __name__ == "__main__":
    import sys

    payment_url = sys.argv[1] if len(sys.argv) > 1 else 'https://checkout.stripe.com/c/pay/cs_live_b1F9f90pytQAzHaZSbHvc3xUeqcLAWaRrPEI9O7gQrwP8NZJzLOXKww0TO#fidnandhYHdWcXxpYCc%2FJ2FgY2RwaXEnKSd2cGd2ZndsdXFsamtQa2x0cGBrYHZ2QGtkZ2lgYSc%2FcXdwYCknYnBkZmRoamlgU2R3bGRrcSc%2FJ2Zqa3F3amknKSdkdWxOYHwnPyd1blppbHNgWjA0V2pEUlJMTVBtcmFAa3dRRn1MSX9pYWlof3YyQURkf2o0bzdSTWhAT1J0X0NxZzFkYW5cN2dUcTNVTG41dmxJMTRtbG1OSlV2QXZuT300XU9zVUFUZE9dNTVkZFFoUzNBNScpJ2N3amhWYHdzYHcnP3F3cGApJ2dkZm5id2pwa2FGamlqdyc%2FJyY1YzVjNDUnKSdpZHxqcHFRfHVgJz8naHBpcWxabHFgaCcpJ2BrZGdpYFVpZGZgbWppYWB3dic%2FcXdwYHgl'
    cdk_code = sys.argv[2] if len(sys.argv) > 2 else "US-QV8Q4-CDEHM-GY7TU-PMDMR-R2JSA"

    captcha_cfg = {
        "yescaptcha_key": os.environ.get("YESCAPTCHA_API_KEY", ""),
    }

    asyncio.run(auto_pay(payment_url, cdk_code, captcha_config=captcha_cfg, headless=True))
