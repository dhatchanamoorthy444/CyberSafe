from playwright.async_api import async_playwright


async def capture_sandbox_proof(url: str) -> dict:
    screenshot_b64 = None
    final_url = url
    page_title = ""
    has_login_form = False

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            page = await context.new_page()
            await page.goto(url, timeout=2000, wait_until="networkidle")
            final_url = page.url
            page_title = await page.title()

            # Check for password inputs
            password_inputs = await page.query_selector_all('input[type="password"]')
            has_login_form = len(password_inputs) > 0

            screenshot_bytes = await page.screenshot(type="png")
            import base64
            screenshot_b64 = base64.b64encode(screenshot_bytes).decode()
            await browser.close()
    except Exception as exc:
        return {
            "screenshot_b64": None,
            "final_url": url,
            "has_login_form": False,
            "page_title": f"Error: {str(exc)}",
        }

    return {
        "screenshot_b64": screenshot_b64,
        "final_url": final_url,
        "has_login_form": has_login_form,
        "page_title": page_title,
    }
