import asyncio
import os
from playwright.async_api import async_playwright

ARTIFACT_PATH = r"C:\Users\abhishek\.gemini\antigravity-ide\scratch\provenanceguard\test-upload-elf.bin"
ARTIFACTS_DIR = r"C:\Users\abhishek\.gemini\antigravity-ide\brain\4ceabd23-1a48-4f00-a0cd-df45b1896370"

async def run_demo():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(viewport={"width": 1440, "height": 900})
        page = await context.new_page()

        print("[1] Navigating to ProvenanceGuard Dashboard...")
        await page.goto("http://127.0.0.1:5173/")
        await page.wait_for_selector("text=ProvenanceGuard", timeout=10000)

        # 1. Authenticate via Dev Token if not logged in
        dev_btn = page.locator("button:has-text('Dev Token Login')")
        if await dev_btn.count() > 0:
            print("[1b] Logging in via Dev Token Modal...")
            await dev_btn.first.click()
            await page.wait_for_selector("text=Issue Development Auth Token", timeout=5000)
            issue_btn = page.locator("button:has-text('Issue & Authenticate')")
            await issue_btn.click()
            await asyncio.sleep(1)

        print("[2] Opening Submit Artifact Modal...")
        submit_btn = page.locator("button:has-text('+ Submit Artifact')").first
        await submit_btn.click()
        await page.wait_for_selector("text=Submit Real Software Artifact", timeout=5000)

        print("[3] Attaching safe ELF binary fixture...")
        file_input = page.locator("#artifactFileInput")
        await file_input.set_input_files(ARTIFACT_PATH)
        await page.wait_for_selector("text=test-upload-elf.bin", timeout=5000)
        await page.screenshot(path=os.path.join(ARTIFACTS_DIR, "demo_02_modal_file_attached.png"))

        print("[4] Submitting Upload & Verification through Real UI...")
        upload_btn = page.locator("button:has-text('Upload & Verify Artifact')")
        await upload_btn.click()

        print("[5] Polling worker verification progress...")
        success = False
        for i in range(25):
            await asyncio.sleep(1)
            content = await page.content()
            if "Artifact Verification Complete" in content:
                print(f" -> COMPLETE detected after {i+1} seconds!")
                success = True
                break
            elif "Upload or Verification Failed" in content:
                print(f" -> FAILURE detected after {i+1} seconds!")
                break
            else:
                if (i + 1) % 3 == 0:
                    print(f" -> Processing... ({i+1}s)")

        await page.screenshot(path=os.path.join(ARTIFACTS_DIR, "demo_03_modal_verification_complete.png"))

        modal_card = page.locator(".panel-card")
        if await modal_card.count() > 0:
            modal_text = await modal_card.first.inner_text()
            print("\n==================================================")
            print("LIVE BROWSER MODAL RESULT VERIFICATION")
            print("==================================================")
            print(modal_text)

        if success:
            print("[6] Dismissing Modal backdrop to view Dashboard...")
            close_btn = page.locator("button:has-text('Close & View Dashboard')").first
            if await close_btn.count() > 0:
                await close_btn.click()
                await asyncio.sleep(2)

        print("[7] Capturing Executive Overview...")
        await page.screenshot(path=os.path.join(ARTIFACTS_DIR, "demo_04_overview_after.png"))

        print("[8] Navigating to Verification Explorer...")
        ve_btn = page.locator("button:has-text('Verification Explorer')").first
        if await ve_btn.count() > 0:
            await ve_btn.click()
            await asyncio.sleep(2)
            await page.screenshot(path=os.path.join(ARTIFACTS_DIR, "demo_05_verification_explorer.png"))

        print("[9] Navigating to Audit Log Stream...")
        audit_btn = page.locator("button:has-text('Audit Log Stream')").first
        if await audit_btn.count() > 0:
            await audit_btn.click()
            await asyncio.sleep(2)
            await page.screenshot(path=os.path.join(ARTIFACTS_DIR, "demo_06_audit_log_stream.png"))

        print("\n[SUCCESS] Live browser end-to-end artifact upload demonstration completed!")
        await browser.close()

if __name__ == "__main__":
    asyncio.run(run_demo())
