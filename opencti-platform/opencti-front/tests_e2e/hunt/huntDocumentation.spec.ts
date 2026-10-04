import { Locator, Page } from '@playwright/test';
import { expect, test } from '../fixtures/baseFixtures';
import HuntsPage from '../model/hunts.pageModel';
import HuntDetailsPage from '../model/huntDetails.pageModel';
import { answerLatestHuntPreview, deleteSeededHunt, SeededHunt, seedHuntWithCompletedRun, startAndReportHuntRun } from '../dataForTesting/hunt.data';

const TRANSLATED_QUERY = 'index=edr sourcetype=sysmon EventCode=1 CommandLine="* -enc *" | stats count by host, user, CommandLine';
const EVIDENCE = [
  { field: 'host.name', value_hash: 'doc-host-1', value_preview: 'FIN-WS-0142', count: 21 },
  { field: 'user.name', value_hash: 'doc-user-1', value_preview: 'svc-backup', count: 17 },
  { field: 'process.command_line', value_hash: 'doc-cmd-1', value_preview: 'powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi...', count: 14 },
];

/**
 * Screenshots of the hunt surfaces for the user documentation (`docs/docs/usage/assets/hunt-*.png`). They are taken on
 * data seeded the way hunt connectors report it and saved with the test results of the run. Two states cannot be
 * produced by a platform without XTM One or with hunts created by other tests: the AI triage proposal of a run and the
 * first use of the Hunts list. For those two screenshots only, the response of the query that reads them is completed
 * (the triage proposal fields, a zero hunt count) before the page renders it.
 */
test.describe('Hunt documentation screenshots', { tag: ['@hunt', '@mutation', '@ee'] }, () => {
  test.describe.configure({ mode: 'serial' });
  // Screenshot conventions of the user documentation: 1440 x 900 at a device scale factor of 2, cropped to the surface
  test.use({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });
  let seeded: SeededHunt;
  let completedRunId: string;
  let failedRunId: string;
  const huntName = 'Encoded PowerShell launched from Office documents';
  const margin = 16;

  const capture = async (page: Page, name: string, surface: Locator, ready: Locator = surface) => {
    await expect(ready).toBeVisible();
    await surface.scrollIntoViewIfNeeded();
    const box = await surface.boundingBox();
    const viewport = page.viewportSize();
    const path = test.info().outputPath(name);
    if (box && viewport && box.height + 2 * margin <= viewport.height) {
      const x = Math.max(0, box.x - margin);
      const y = Math.max(0, box.y - margin);
      const clip = { x, y, width: Math.min(viewport.width - x, box.width + 2 * margin), height: Math.min(viewport.height - y, box.height + 2 * margin) };
      await page.screenshot({ path, animations: 'disabled', clip });
    } else {
      await surface.screenshot({ path, animations: 'disabled' });
    }
  };

  interface CompletedData {
    hunts?: { pageInfo: { globalCount: number } };
    huntRun?: Record<string, unknown>;
  }

  const completeOperation = async (page: Page, operation: string, complete: (data: CompletedData) => void) => {
    const operationPattern = new RegExp(`\\bquery ${operation}\\b`);
    await page.route('**/graphql', async (route) => {
      const body = route.request().postDataJSON();
      const matches = body?.id === operation || (typeof body?.query === 'string' && operationPattern.test(body.query));
      if (!matches) {
        await route.fallback();
        return;
      }
      const response = await route.fetch();
      const json = await response.json();
      complete(json.data);
      await route.fulfill({ response, json });
    });
  };

  test.beforeAll(async ({ request }) => {
    seeded = await seedHuntWithCompletedRun(request, huntName, { connector: 'Splunk hunt', securityPlatform: 'Splunk Enterprise - SOC' });
    completedRunId = await startAndReportHuntRun(request, seeded, `
      status: completed, query_language: "spl", translated_query: ${JSON.stringify(TRANSLATED_QUERY)},
      hits_count: 42, distinct_entities: 3, cost_ms: 2140,
      evidence_sample: [${EVIDENCE.map((item) => `{ field: "${item.field}", value_hash: "${item.value_hash}", value_preview: ${JSON.stringify(item.value_preview)}, count: ${item.count} }`).join(', ')}]
    `);
    failedRunId = await startAndReportHuntRun(request, seeded, `
      status: failed, query_language: "spl", translated_query: ${JSON.stringify(TRANSLATED_QUERY)},
      error: ${JSON.stringify('HuntExecutionError: Splunk returned HTTP 400: Error in \'search\' command: Unable to parse the search: unbalanced quotes.')}
    `);
  });

  test.afterAll(async ({ request }) => {
    if (seeded) {
      await deleteSeededHunt(request, seeded);
    }
  });

  test('Hunts list, populated and on first use', async ({ page }) => {
    const huntsPage = new HuntsPage(page);
    await huntsPage.goto();
    await capture(page, 'hunt-list-populated.png', huntsPage.getPage(), huntsPage.getItemFromList(huntName).first());
    await completeOperation(page, 'HuntsFirstUseQuery', (data) => {
      if (data.hunts) {
        data.hunts.pageInfo.globalCount = 0;
      }
    });
    await huntsPage.goto();
    await capture(page, 'hunt-list-first-use.png', page.getByTestId('hunts-first-use'));
  });

  test('Hunt overview, Sigma validation and translation preview', async ({ page, request }) => {
    const huntDetails = new HuntDetailsPage(page);
    await page.goto(`/dashboard/defense/hunts/${seeded.huntId}`);
    await capture(page, 'hunt-overview.png', huntDetails.getOverview());
    await huntDetails.tabs.goToLogicTab();
    await capture(page, 'hunt-logic-sigma-validation.png', huntDetails.getLogicPage(), huntDetails.getLogicSigmaValidation().getByText('Valid Sigma rule'));
    await page.getByTestId('hunt-translation-preview-start').click();
    await expect.poll(() => answerLatestHuntPreview(request, seeded.huntId, TRANSLATED_QUERY), { timeout: 30000 }).toBe(true);
    const preview = page.getByTestId('hunt-translation-preview');
    await capture(page, 'hunt-logic-translation-preview.png', preview, preview.getByText('index=edr sourcetype=sysmon'));
  });

  test('Completed run with its evidence and the AI triage proposal', async ({ page }) => {
    await completeOperation(page, 'HuntRunDrawerQuery', (data) => {
      Object.assign(data.huntRun ?? {}, {
        verdict_proposal: 'true_positive',
        verdict_proposal_confidence: 82,
        verdict_proposal_agent: 'OpenCTI Hunt Triage',
        verdict_proposal_rationale: 'The encoded PowerShell runs under a service account on a finance workstation, outside any maintenance window, and none of the benign patterns of the hunt matches. The 42 hits on three entities are consistent with the hypothesis.',
      });
    });
    await new HuntDetailsPage(page).gotoRun(seeded.huntId, completedRunId);
    await capture(page, 'hunt-run-completed-triage.png', page.getByTestId('hunt-run-drawer'), page.getByTestId('hunt-run-triage'));
  });

  test('Failed run', async ({ page }) => {
    await new HuntDetailsPage(page).gotoRun(seeded.huntId, failedRunId);
    await capture(page, 'hunt-run-failed.png', page.getByTestId('hunt-run-drawer'), page.getByTestId('hunt-run-failure'));
  });

  test('Schedule field', async ({ page }) => {
    const huntDetails = new HuntDetailsPage(page);
    await page.goto(`/dashboard/defense/hunts/${seeded.huntId}`);
    await expect(huntDetails.getOverview()).toBeVisible();
    await page.getByRole('button', { name: 'Update' }).first().click();
    const scheduleField = page.getByTestId('hunt-schedule-field');
    await scheduleField.scrollIntoViewIfNeeded();
    await capture(page, 'hunt-schedule-field.png', scheduleField);
  });

  test('Hunted platform on the connector page', async ({ page }) => {
    await page.goto(`/dashboard/data/ingestion/connectors/${seeded.connectorId}`);
    await capture(page, 'hunt-connector-page.png', page.getByTestId('connector-hunt-card'), page.getByTestId('connector-hunt-runs'));
  });
});
