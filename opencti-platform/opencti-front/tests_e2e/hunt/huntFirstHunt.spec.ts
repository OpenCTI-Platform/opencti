import { Locator, Page } from '@playwright/test';
import { expect, test } from '../fixtures/baseFixtures';
import {
  answerHuntPreview,
  deleteHunt,
  deleteSeededHuntPlatform,
  findQueuedHuntPreview,
  HUNT_SIGMA_RULE,
  reportIndicatorRun,
  SeededHuntPlatform,
  seedDraftHuntWithoutLogic,
  seedHuntPlatform,
} from '../dataForTesting/hunt.data';
import { getSettings, getThemeIdByName, patchSettings } from '../dataForTesting/settings.data';

const TRANSLATED_QUERY = 'index=edr sourcetype=sysmon EventCode=1 CommandLine="* -enc *"';

const PASTED_VALUES = [
  '198.51.100.23',
  'login-microsoftonline[.]example-cdn.com',
  'hxxps://login-microsoftonline.example-cdn.com/owa/auth.php',
  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  'not-an-indicator',
].join('\n');

/**
 * The first hunt of a product manager, as the documentation page "Your first hunt" walks through it: an indicator hunt
 * from pasted values to its first run and its results per value, then a hunt whose Activate is blocked until its
 * checklist is complete. Every step is captured for the documentation (`docs/docs/usage/assets/first-hunt-*.png`), in
 * the dark theme then the light one.
 */
test.describe('Your first hunt', { tag: ['@hunt', '@mutation', '@ce'] }, () => {
  test.describe.configure({ mode: 'serial' });
  test.use({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });
  let platform: SeededHuntPlatform;
  const createdHuntIds: string[] = [];

  const capture = async (page: Page, name: string, surface: Locator, ready: Locator = surface) => {
    await expect(ready).toBeVisible();
    await surface.scrollIntoViewIfNeeded();
    await surface.screenshot({ path: test.info().outputPath(name), animations: 'disabled' });
  };

  // The first-use page shows while the platform holds no hunt; other tests create hunts, so the count is read as zero
  const showFirstUse = async (page: Page) => {
    await page.route('**/graphql', async (route) => {
      const body = route.request().postDataJSON();
      const isFirstUseQuery = body?.id === 'HuntsFirstUseQuery' || (typeof body?.query === 'string' && /\bquery HuntsFirstUseQuery\b/.test(body.query));
      if (!isFirstUseQuery) {
        await route.fallback();
        return;
      }
      const response = await route.fetch();
      const json = await response.json();
      if (json.data?.hunts) json.data.hunts.pageInfo.globalCount = 0;
      await route.fulfill({ response, json });
    });
  };

  const indicatorHuntToFirstRun = async (page: Page, suffix: string) => {
    await showFirstUse(page);
    await page.goto('/dashboard/defense/hunts');
    const firstUse = page.getByTestId('hunts-first-use');
    await capture(page, `first-hunt-start${suffix}.png`, firstUse, firstUse.getByTestId('hunts-first-use-starting-points'));
    await expect(firstUse.getByTestId('hunts-setup-connectors')).toHaveAttribute('data-status', 'met');

    // Step 1: what to look for, pasted values detected and refanged, the rest left out
    await page.getByTestId('hunts-first-use-indicators-start').click();
    const dialog = page.getByTestId('hunt-guided-indicators');
    await expect(dialog.getByTestId('hunt-guided-next')).toBeDisabled();
    await expect(dialog.getByTestId('hunt-guided-next-reason')).toHaveText('Add the indicators or observables to look for');
    await dialog.getByLabel('Paste values').fill(PASTED_VALUES);
    const summary = dialog.getByTestId('hunt-ioc-text-summary');
    await expect(summary.getByText('4 values recognized')).toBeVisible();
    await expect(dialog.getByTestId('hunt-ioc-text-invalid')).toContainText('not-an-indicator');
    await capture(page, `first-hunt-indicators-step-1${suffix}.png`, dialog, summary);

    // Step 2: where and how far back, with the hunt connectors that can run it
    await dialog.getByTestId('hunt-guided-next').click();
    await expect(dialog.getByTestId('hunt-guided-connectors')).toContainText('Splunk Enterprise - first hunt');
    await capture(page, `first-hunt-indicators-step-2${suffix}.png`, dialog, dialog.getByTestId('hunt-guided-scope'));

    // Step 3: start, the hunt is created active and its first run starts
    await dialog.getByTestId('hunt-guided-next').click();
    await dialog.getByLabel('Name').fill(`First indicator hunt${suffix}`);
    await capture(page, `first-hunt-indicators-step-3${suffix}.png`, dialog, dialog.getByTestId('hunt-guided-start'));
    await dialog.getByTestId('hunt-guided-submit').click();
    await expect(page).toHaveURL(/\/dashboard\/defense\/hunts\/[^/]+\/runs\/[^/]+$/);
    const [, huntId, runId] = /\/hunts\/([^/]+)\/runs\/([^/]+)$/.exec(page.url()) ?? [];
    createdHuntIds.push(huntId);
    return { huntId, runId };
  };

  const resultsPerValue = async (page: Page, huntId: string, runId: string, suffix: string) => {
    await page.setViewportSize({ width: 1440, height: 1800 });
    await page.goto(`/dashboard/defense/hunts/${huntId}/runs/${runId}`);
    const results = page.getByTestId('hunt-run-ioc-results');
    await expect(results.getByTestId('hunt-run-ioc-summary')).toContainText('2 of 4 values seen', { timeout: 30000 });
    await expect(results.locator('[data-verdict="not_searched"]')).toHaveCount(1);
    await capture(page, `first-hunt-results-per-value${suffix}.png`, results);
    await page.setViewportSize({ width: 1440, height: 900 });
    // The Logic tab of the hunt lists the values the next run looks for
    await page.goto(`/dashboard/defense/hunts/${huntId}/logic`);
    const values = page.getByTestId('hunt-ioc-values');
    await expect(values.getByText('4 values to look for')).toBeVisible();
    await capture(page, `first-hunt-indicators-logic${suffix}.png`, page.getByTestId('hunt-logic-page'), values);
  };

  const activationExplainsItself = async (page: Page, request: Parameters<typeof seedDraftHuntWithoutLogic>[0], suffix: string) => {
    const huntId = await seedDraftHuntWithoutLogic(request, `Encoded PowerShell from Office documents${suffix}`, platform.securityPlatformId);
    createdHuntIds.push(huntId);
    await page.goto(`/dashboard/defense/hunts/${huntId}`);
    const header = page.getByTestId('hunt-status-header');
    // Activate stays visible, disabled with its reason next to it, and the checklist names what to do
    await expect(header.getByTestId('hunt-status-to-active')).toBeDisabled();
    await expect(header.getByTestId('hunt-primary-blocked-reason')).toHaveText('1 item to complete');
    const logic = header.getByTestId('hunt-readiness-logic');
    await expect(logic).toHaveAttribute('data-status', 'unmet');
    await expect(logic).toContainText('Add a Sigma rule or a native query');
    await expect(header.getByTestId('hunt-readiness-connector')).toHaveAttribute('data-status', 'met');
    await expect(header.getByTestId('hunt-status-model')).toContainText('The hunt is being written; it never runs.');
    await capture(page, `first-hunt-activation-blocked${suffix}.png`, header);

    // The checklist links to the Logic tab, which offers Activate as soon as the rule is saved
    await logic.getByTestId('hunt-readiness-open-logic').click();
    await expect(page.getByTestId('hunt-logic-missing')).toContainText('Add a Sigma rule or a native query');
    await page.getByTestId('hunt-logic-sigma').locator('textarea').fill(HUNT_SIGMA_RULE);
    await expect(page.getByTestId('hunt-sigma-validation').getByText('Valid Sigma rule')).toBeVisible();
    await page.getByTestId('hunt-logic-save-top').click();
    const saved = page.getByTestId('hunt-logic-saved');
    await expect(saved).toContainText('The logic is saved, the hunt is still a draft');
    await capture(page, `first-hunt-sigma-saved${suffix}.png`, page.getByTestId('hunt-logic-page'), saved.getByTestId('hunt-logic-activate'));
    await saved.getByTestId('hunt-logic-activate').click();
    await expect(header.getByTestId('hunt-status-chip')).toHaveText('Active');
    // The activation queues a translation check of the saved rule, which its hunt connector answers
    let translationCheckId: string | undefined;
    await expect.poll(async () => {
      translationCheckId = await findQueuedHuntPreview(request, huntId);
      return translationCheckId;
    }).toBeDefined();
    await answerHuntPreview(request, translationCheckId as string, TRANSLATED_QUERY);
    await page.reload();
    await expect(header.getByTestId('hunt-readiness-summary')).toHaveText('Ready to run');
    await capture(page, `first-hunt-activation-ready${suffix}.png`, header);
  };

  test.beforeAll(async ({ request }) => {
    platform = await seedHuntPlatform(request, 'Splunk Enterprise - first hunt');
  });

  test.afterAll(async ({ request }) => {
    for (const huntId of createdHuntIds) {
      await deleteHunt(request, huntId).catch(() => undefined);
    }
    if (platform) {
      await deleteSeededHuntPlatform(request, platform);
    }
  });

  test('An indicator hunt from pasted values to its results per value', async ({ page, request }) => {
    const { huntId, runId } = await indicatorHuntToFirstRun(page, '');
    await reportIndicatorRun(request, runId, {
      '198.51.100.23': { hits: 14, hosts: ['FIN-WS-0142', 'FIN-WS-0207'] },
      'login-microsoftonline.example-cdn.com': { hits: 3, hosts: ['FIN-WS-0142'] },
    }, ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']);
    await resultsPerValue(page, huntId, runId, '');
  });

  test('Activate explains what the hunt still needs', async ({ page, request }) => {
    await activationExplainsItself(page, request, '');
  });

  test('Your first hunt in the light theme', async ({ page, request }) => {
    const settings = await getSettings(request);
    const initialThemeId = settings.platform_theme?.id ?? await getThemeIdByName(request, 'Filigran Dark');
    await patchSettings(request, settings.id, 'platform_theme', await getThemeIdByName(request, 'Filigran Light'));
    try {
      const { huntId, runId } = await indicatorHuntToFirstRun(page, '-light');
      await reportIndicatorRun(request, runId, {
        '198.51.100.23': { hits: 14, hosts: ['FIN-WS-0142', 'FIN-WS-0207'] },
        'login-microsoftonline.example-cdn.com': { hits: 3, hosts: ['FIN-WS-0142'] },
      }, ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']);
      await resultsPerValue(page, huntId, runId, '-light');
      await activationExplainsItself(page, request, '-light');
    } finally {
      await patchSettings(request, settings.id, 'platform_theme', initialThemeId);
    }
  });
});
