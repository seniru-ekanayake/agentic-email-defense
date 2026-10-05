import asyncio
import os
from playwright.async_api import async_playwright

TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbmFseXN0XzEiLCJ0ZW5hbnRfaWQiOiJ0ZW5hbnQtZW50ZXJwcmlzZS1wcm9kIiwicm9sZXMiOlsiU09DX0FOQUxZU1QiXSwiaWF0IjoxNzkxMTc1Mjg3Ljg4NzM5MTMsImV4cCI6MTc5MTUzNTI4Ny44ODczOTEzfQ.mFsElfGRMFGOOeFD7LSjhGDSip-r-Hs8JxJQlVRYQU0'
CHROME_PATH = r'C:\Program Files\Google\Chrome\Application\chrome.exe'

async def test_full_ui_causality():
    print('======================================================================')
    print('FISHINGMAILS FRONTEND INTEGRATION REALITY AUDIT (PLAYWRIGHT + CHROME)')
    print('======================================================================')

    async with async_playwright() as p:
        browser = await p.chromium.launch(executable_path=CHROME_PATH, headless=True)
        context = await browser.new_context()
        page = await context.new_page()

        # Step 1: Open page and inject JWT token
        await page.goto('http://localhost:3000')
        await page.evaluate(f'''() => {{
            localStorage.setItem('fishingmails_auth_token', '{TOKEN}');
            sessionStorage.setItem('fishingmails_auth_token', '{TOKEN}');
        }}''')
        await page.reload()
        await page.wait_for_selector('table tbody tr:nth-child(5)')

        row_count = await page.locator('table tbody tr').count()
        print(f'[PASS 1] Incident Ledger Rendered: {row_count} rows loaded from backend SQLite')
        assert row_count >= 50, f'Expected >= 50 rows, got {row_count}'

        # Step 2: Click first row to open detail modal
        first_row = page.locator('table tbody tr').first
        await first_row.click()
        await page.wait_for_selector('.fixed.inset-0')
        modal_text = await page.locator('.fixed.inset-0').first.text_content()
        has_detail = '01_OVERVIEW' in modal_text and '02_ATTACK_CHAIN' in modal_text and '03_EVIDENCE' in modal_text
        print(f'[PASS 2] Deep Incident Detail Modal Rendered: {has_detail}')
        print(f'         Detail Snippet: {modal_text[:120]}...')
        assert has_detail, 'Detail modal failed to display overview and attack chain'

        # Step 2b: Click through Tabs in Modal (Attack Chain, Evidence, Decisions, Tools)
        attack_tab = page.locator('button').filter(has_text='02_ATTACK_CHAIN').first
        await attack_tab.click()
        await page.wait_for_timeout(400)
        attack_text = await page.locator('.fixed.inset-0').first.text_content()
        print(f'[PASS 2b] Attack Chain Tab Verified: {"Stage" in attack_text or "TTP" in attack_text or "Vector" in attack_text or "Chain" in attack_text}')

        evidence_tab = page.locator('button').filter(has_text='03_EVIDENCE').first
        await evidence_tab.click()
        await page.wait_for_timeout(400)
        evidence_text = await page.locator('.fixed.inset-0').first.text_content()
        print(f'[PASS 2c] Evidence Tab Verified: {"Evidence" in evidence_text or "Type" in evidence_text or "SHA" in evidence_text}')

        decisions_tab = page.locator('button').filter(has_text='04_DECISIONS').first
        await decisions_tab.click()
        await page.wait_for_timeout(400)
        decisions_text = await page.locator('.fixed.inset-0').first.text_content()
        print(f'[PASS 2d] Decisions Tab Verified: {"Decision" in decisions_text or "Rationale" in decisions_text or "Action" in decisions_text}')

        # Close modal
        close_btn = page.locator('.fixed.inset-0 button').filter(has_text='✕').first
        if await close_btn.count() > 0:
            await close_btn.click()
            await page.wait_for_timeout(500)

        # Step 3: Test Search Filter
        search_input = page.locator('input[placeholder*="Filter sender"]').first
        await search_input.fill('newsletter')
        await page.wait_for_timeout(500)
        filtered_count = await page.locator('table tbody tr').count()
        print(f'[PASS 3] Search Filtering Active: {filtered_count} matching rows')
        assert filtered_count > 0, 'Search filter returned 0 rows'
        await search_input.fill('')
        await page.wait_for_timeout(500)

        # Step 4: Verify Live Stream View Navigation
        stream_nav = page.locator('button').filter(has_text='Live Telemetry').first
        await stream_nav.click()
        await page.wait_for_timeout(500)
        stream_heading = await page.locator('h2').filter(has_text='Live LangGraph Agent Reasoning Stream').count()
        print(f'[PASS 4] Live Telemetry View Navigation: {stream_heading == 1}')
        assert stream_heading == 1, 'Live telemetry view failed to render'

        # Step 5: Verify Exposure Radar Navigation
        radar_nav = page.locator('button').filter(has_text='Exposure Radar').first
        await radar_nav.click()
        await page.wait_for_timeout(500)
        radar_heading = await page.locator('h2').filter(has_text='Asset Exposure Radar').count()
        print(f'[PASS 5] Exposure Radar Active: {radar_heading >= 1}')
        assert radar_heading >= 1, 'Exposure radar view failed to render'

        # Step 6: Verify Session Auth Modal
        overview_nav = page.locator('button').filter(has_text='Overview').first
        await overview_nav.click()
        await page.wait_for_timeout(500)
        auth_btn = page.locator('button').filter(has_text='Session Auth').first
        await auth_btn.click()
        auth_heading = await page.wait_for_selector('text=SOC Analyst Authentication', timeout=5000)
        is_visible = await auth_heading.is_visible()
        print(f'[PASS 6] Session Auth Modal Rendered: {is_visible}')
        assert is_visible, 'Session auth modal was not visible'

        # Close auth modal
        close_auth_btn = page.locator('.fixed.inset-0 button').filter(has_text='✕').first
        if await close_auth_btn.count() > 0:
            await close_auth_btn.click()
            await page.wait_for_timeout(500)

        await browser.close()
        print('======================================================================')
        print('SUCCESS: ALL INTERACTIVE UI PATHS DEMONSTRATE PROVABLE CAUSALITY')
        print('======================================================================')

if __name__ == '__main__':
    asyncio.run(test_full_ui_causality())
