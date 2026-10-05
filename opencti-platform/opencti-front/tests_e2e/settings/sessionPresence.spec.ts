import type { Browser, BrowserContext, Page, TestInfo } from '@playwright/test';
import { expect, prefixUrl, test } from '../fixtures/baseFixtures';
import DashboardPage from '../model/dashboard.pageModel';
import LoginFormPageModel from '../model/form/loginForm.pageModel';
import { getSettings, patchSettings } from '../dataForTesting/settings.data';

// Must match app:session_presence:grace_period of the tested platform
const GRACE_PERIOD = 30000;
const SETTLE_DELAY = 10000;

/**
 * Resolves once the page GraphQL WebSocket is acknowledged by the platform,
 * meaning the tab is registered as a presence of its session.
 */
const waitForPresence = (page: Page) => new Promise<void>((resolve) => {
  page.on('websocket', (webSocket) => {
    webSocket.on('framereceived', (frame) => {
      if (String(frame.payload).includes('connection_ack')) {
        resolve();
      }
    });
  });
});

const newTab = async (context: BrowserContext) => {
  const page = await context.newPage();
  const originalGoto = page.goto.bind(page);
  page.goto = (url, options) => originalGoto(prefixUrl(url), options);
  return page;
};

const openTab = async (context: BrowserContext) => {
  const page = await newTab(context);
  const presence = waitForPresence(page);
  await page.goto('/dashboard');
  await expect(new DashboardPage(page).getPage()).toBeVisible();
  await presence;
  return page;
};

/**
 * Logs in a fresh browser context, so every test drives its own sessions
 * and never the admin session shared by the other specs.
 */
const openSession = async (browser: Browser, testInfo: TestInfo) => {
  const { baseURL, viewport, ignoreHTTPSErrors } = testInfo.project.use;
  const context = await browser.newContext({ baseURL, viewport, ignoreHTTPSErrors, storageState: { cookies: [], origins: [] } });
  const tab = await newTab(context);
  const presence = waitForPresence(tab);
  await tab.goto('/');
  await new LoginFormPageModel(tab).login();
  await expect(new DashboardPage(tab).getPage()).toBeVisible();
  await presence;
  return { context, tab };
};

const isSessionAlive = async (context: BrowserContext) => {
  const response = await context.request.post(prefixUrl('/graphql'), { data: { query: '{ me { id } }' } });
  const result = await response.json();
  return !!result.data?.me?.id;
};

test.describe('Logout when the last tab is closed', { tag: ['@ce'] }, () => {
  test.describe.configure({ timeout: 5 * 60 * 1000 });

  let settingsId: string;

  test.beforeEach(async ({ request }) => {
    settingsId = (await getSettings(request)).id;
    await patchSettings(request, settingsId, 'platform_session_presence_enabled', 'true');
  });

  test.afterEach(async ({ request }) => {
    await patchSettings(request, settingsId, 'platform_session_presence_enabled', 'false');
  });

  test('should logout a session only once all its tabs are closed', async ({ browser }, testInfo) => {
    const { context: session, tab: firstTab } = await openSession(browser, testInfo);
    const { context: otherSession } = await openSession(browser, testInfo);
    const secondTab = await openTab(session);

    // Another tab still holds the session
    await firstTab.close();
    await secondTab.waitForTimeout(GRACE_PERIOD + SETTLE_DELAY);
    expect(await isSessionAlive(session)).toBe(true);

    // Last tab of the session closed, the other session is untouched
    await secondTab.close();
    await expect.poll(() => isSessionAlive(session), { timeout: GRACE_PERIOD + SETTLE_DELAY, intervals: [2000] }).toBe(false);
    expect(await isSessionAlive(otherSession)).toBe(true);

    await session.close();
    await otherSession.close();
  });

  test('should keep the session when its last tab is refreshed', async ({ browser }, testInfo) => {
    const { context: session, tab } = await openSession(browser, testInfo);

    const presence = waitForPresence(tab);
    await tab.reload();
    await presence;
    await tab.waitForTimeout(GRACE_PERIOD + SETTLE_DELAY);
    expect(await isSessionAlive(session)).toBe(true);

    await session.close();
  });
});
