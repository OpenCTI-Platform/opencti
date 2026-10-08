import { APIRequestContext, Locator, Page } from '@playwright/test';
import { expect, test } from '../fixtures/baseFixtures';
import HuntsPage from '../model/hunts.pageModel';
import HuntDetailsPage from '../model/huntDetails.pageModel';
import {
  answerHuntPreview,
  deleteHunt,
  deleteSeededHunt,
  deleteSeededHuntPlatform,
  SeededHunt,
  seedAgentDraftHunt,
  seedHuntConnectorWithSetup,
  seedHuntWithCompletedRun,
  setHuntRunVerdict,
  startAndReportHuntRun,
  testHuntConnection,
} from '../dataForTesting/hunt.data';
import { getSettings, getThemeIdByName, patchSettings } from '../dataForTesting/settings.data';

const TRANSLATED_QUERY = 'index=edr sourcetype=sysmon EventCode=1 CommandLine="* -enc *"';
// What the Splunk hunt connector reports when the role of its account lacks the search capability
const ACCESS_DENIED_ERROR = 'HuntAccessDeniedError: Access denied: The platform search was refused (403): the role of the account needs the search capability and read access to the app SPLUNK_HUNT_APP, in Settings > Roles';
const EVIDENCE = [
  { field: 'host.name', value_hash: 'doc-host-1', value_preview: 'FIN-WS-0142', count: 21 },
  { field: 'user.name', value_hash: 'doc-user-1', value_preview: 'svc-backup', count: 17 },
  { field: 'process.command_line', value_hash: 'doc-cmd-1', value_preview: 'powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi...', count: 14 },
];

/**
 * Screenshots of the hunt surfaces for the user documentation (`docs/docs/usage/assets/hunt-*.png`). They are taken on
 * data seeded the way hunt connectors report it and saved with the test results of the run. Two states cannot be
 * produced by a platform without XTM One or with hunts created by other tests: the AI triage proposal of a run and the
 * first use of the Hunts list. For those two screenshots only, the responses that read them are completed (the triage
 * proposal fields and the XTM One availability, a zero hunt count) before the page renders them.
 */
test.describe('Hunt documentation screenshots', { tag: ['@hunt', '@mutation', '@ee'] }, () => {
  test.describe.configure({ mode: 'serial' });
  // Screenshot conventions of the user documentation: 1440 x 900 at a device scale factor of 2, cropped to the surface
  test.use({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });
  let seeded: SeededHunt;
  let completedRunId: string;
  let failedRunId: string;
  let partialRunId: string;
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
    // One run per verdict for the Runs tab: benign (no hit), true positive (set by an analyst), and a run whose
    // platform returned partial results
    await startAndReportHuntRun(request, seeded, 'status: completed, query_language: "spl", hits_count: 0, truncated: false, cost_ms: 980');
    const confirmedRunId = await startAndReportHuntRun(request, seeded, `
      status: completed, query_language: "spl", hits_count: 5, distinct_entities: 1, cost_ms: 1530,
      evidence_sample: [{ field: "host.name", value_hash: "doc-host-2", value_preview: "FIN-WS-0207", count: 5 }]
    `);
    await setHuntRunVerdict(request, confirmedRunId, 'true_positive', 'Confirmed with the workstation owner: no maintenance task runs encoded PowerShell.');
    partialRunId = await startAndReportHuntRun(request, seeded, `
      status: completed, query_language: "spl", translated_query: ${JSON.stringify(TRANSLATED_QUERY)},
      hits_count: 7, distinct_entities: 2, cost_ms: 30000, truncated: true,
      evidence_sample: [{ field: "host.name", value_hash: "doc-host-3", value_preview: "FIN-WS-0311", count: 7 }]
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
    // The whole overview fits, with the hunt header and tabs
    await page.setViewportSize({ width: 1440, height: 1800 });
    await page.goto(`/dashboard/defense/hunts/${seeded.huntId}`);
    await capture(page, 'hunt-overview.png', huntDetails.getPage(), huntDetails.getOverview());
    await page.setViewportSize({ width: 1440, height: 900 });
    await huntDetails.tabs.goToLogicTab();
    await capture(page, 'hunt-logic-sigma-validation.png', huntDetails.getLogicPage(), huntDetails.getLogicSigmaValidation().getByText('Valid Sigma rule'));
    // The hunt was created active, which queued a translation check of its own: answer the run this page starts
    const previewStarted = page.waitForResponse((response) => response.url().includes('/graphql')
      && (response.request().postData() ?? '').includes('HuntTranslationPreviewTestQueryMutation'));
    await page.getByTestId('hunt-translation-preview-start').click();
    const started = await (await previewStarted).json() as { data: { huntTestQuery: { id: string } } };
    await answerHuntPreview(request, started.data.huntTestQuery.id, TRANSLATED_QUERY);
    const preview = page.getByTestId('hunt-translation-preview');
    await capture(page, 'hunt-logic-translation-preview.png', preview, preview.getByText('index=edr sourcetype=sysmon'));
  });

  test('Completed run with its evidence and the AI triage proposal', async ({ page }) => {
    // The whole drawer fits, evidence included
    await page.setViewportSize({ width: 1440, height: 2000 });
    await page.route('**/chatbot/config', async (route) => {
      const response = await route.fetch();
      const json = response.ok() ? await response.json() : {};
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ ...json, xtm_one_configured: true }) });
    });
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
    await page.setViewportSize({ width: 1440, height: 1600 });
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
    // A cron schedule with its preview, left unsaved. The options are picked by their role: the label of the field
    // carries the Enterprise Edition marker, so its list of options has no accessible name.
    await scheduleField.getByRole('combobox', { name: 'Schedule' }).click();
    await page.getByRole('option', { name: 'Scheduled (cron)', exact: true }).click();
    await scheduleField.getByLabel('Cron expression (UTC)').fill('0 */6 * * *');
    await capture(page, 'hunt-schedule-field.png', scheduleField);
  });

  test('Hunted platform on the connector page', async ({ page }) => {
    await page.goto(`/dashboard/data/ingestion/connectors/${seeded.connectorId}`);
    await capture(page, 'hunt-connector-page.png', page.getByTestId('connector-hunt-card'), page.getByTestId('connector-hunt-runs'));
  });

  test('Draft banner of a hunt proposed by an agent', async ({ page, request }) => {
    const draftHuntId = await seedAgentDraftHunt(request, 'Encoded PowerShell proposed by the Hunt Planner');
    try {
      await page.goto(`/dashboard/defense/hunts/${draftHuntId}`);
      const banner = page.getByTestId('hunt-draft-banner');
      await capture(page, 'hunt-draft-banner.png', banner, banner.getByText('This hunt is a draft'));
    } finally {
      await deleteHunt(request, draftHuntId);
    }
  });

  // The Defense hub, the runs with their verdicts and a run with partial results, in the dark theme then the light one
  const captureHubSurfaces = async (page: Page, suffix: string) => {
    const huntsPage = new HuntsPage(page);
    const huntDetails = new HuntDetailsPage(page);
    await huntsPage.goto();
    await expect(huntsPage.getItemFromList(huntName).first()).toBeVisible();
    await page.screenshot({ path: test.info().outputPath(`hunt-defense-hub${suffix}.png`), animations: 'disabled' });
    await page.goto(`/dashboard/defense/hunts/${seeded.huntId}`);
    await capture(page, `hunt-detail${suffix}.png`, huntDetails.getPage(), huntDetails.getOverview());
    await huntDetails.tabs.goToRunsTab();
    const runs = page.getByTestId('hunt-runs-page');
    await capture(page, `hunt-runs-verdicts${suffix}.png`, runs, runs.getByText('True positive').first());
    await page.setViewportSize({ width: 1440, height: 1600 });
    await huntDetails.gotoRun(seeded.huntId, partialRunId);
    await capture(page, `hunt-run-partial-results${suffix}.png`, page.getByTestId('hunt-run-drawer'), page.getByTestId('hunt-run-partial-results'));
    await expect(page.getByTestId('hunt-run-drawer').getByText('At least 7')).toBeVisible();
    await page.setViewportSize({ width: 1440, height: 900 });
  };

  test('Defense hub, verdicts and partial results', async ({ page }) => {
    await captureHubSurfaces(page, '');
  });

  test('Defense hub, verdicts and partial results in the light theme', async ({ page, request }) => {
    // The platform theme is shared by every test: captured first and restored whatever happens
    const settings = await getSettings(request);
    const initialThemeId = settings.platform_theme?.id ?? await getThemeIdByName(request, 'Filigran Dark');
    await patchSettings(request, settings.id, 'platform_theme', await getThemeIdByName(request, 'Filigran Light'));
    try {
      await captureHubSurfaces(page, '-light');
    } finally {
      await patchSettings(request, settings.id, 'platform_theme', initialThemeId);
    }
  });

  // Setup clarity: the permissions a hunt connector needs, its connection test failed then passed, a run refused by the
  // platform and the help of the hunt form. Each theme registers its own connector, so each starts untested.
  let accessDeniedRunId: string | undefined;
  const captureSetupSurfaces = async (page: Page, request: APIRequestContext, suffix: string) => {
    const setup = await seedHuntConnectorWithSetup(request, 'Splunk hunt - EU SOC', 'Splunk Enterprise - EU SOC');
    try {
      await page.goto(`/dashboard/data/ingestion/connectors/${setup.connectorId}`);
      const card = page.getByTestId('connector-hunt-card');
      const permissions = card.getByTestId('connector-hunt-permissions');
      // Untested: the permissions are open, next to the connection test
      await expect(permissions).toHaveAttribute('data-open', 'true');
      await capture(page, `hunt-connector-permissions${suffix}.png`, card, permissions.getByText('srchIndexesAllowed'));
      await testHuntConnection(request, setup.connectorId, [
        { name: 'Authentication', ok: true, message: 'Splunk accepted the credentials of the connector.' },
        { name: 'search', ok: false, message: 'Access denied: the roles of svc_opencti_hunt lack the search capability: add it to one of its roles in Settings > Roles.' },
      ]);
      await page.reload();
      await capture(page, `hunt-connection-test-failed${suffix}.png`, card, card.locator('[data-testid="connector-hunt-check-status"][data-status="failed"]'));
      await expect(permissions).toHaveAttribute('data-open', 'true');
      await testHuntConnection(request, setup.connectorId, [
        { name: 'Authentication', ok: true, message: 'Splunk accepted the credentials of the connector.' },
        { name: 'search', ok: true, message: 'The roles of svc_opencti_hunt hold the search capability.' },
        { name: 'Search', ok: true, message: 'The account can run searches on the platform.' },
      ]);
      await page.reload();
      await capture(page, `hunt-connection-test-passed${suffix}.png`, card, card.locator('[data-testid="connector-hunt-check-status"][data-status="passed"]'));
      // Once a test passed, the permissions fold
      await expect(permissions).toHaveAttribute('data-open', 'false');
    } finally {
      await deleteSeededHuntPlatform(request, setup);
    }
    accessDeniedRunId ??= await startAndReportHuntRun(request, seeded, `status: failed, query_language: "spl", error: ${JSON.stringify(ACCESS_DENIED_ERROR)}`);
    await page.setViewportSize({ width: 1440, height: 1600 });
    await new HuntDetailsPage(page).gotoRun(seeded.huntId, accessDeniedRunId);
    const failure = page.locator('[data-testid="hunt-run-failure"][data-kind="access"]');
    await capture(page, `hunt-run-access-denied${suffix}.png`, page.getByTestId('hunt-run-drawer'), failure.getByTestId('hunt-run-test-connection'));
    // The whole creation form, each field with its help; the Learn more of the documentation is in the drawer header
    await page.setViewportSize({ width: 1440, height: 2200 });
    const huntsPage = new HuntsPage(page);
    await huntsPage.goto();
    await huntsPage.openCreateForm();
    const form = page.getByTestId('hunt-creation-form');
    await capture(page, `hunt-form-help${suffix}.png`, form, page.getByTestId('hunt-creation-learn-more'));
    await page.setViewportSize({ width: 1440, height: 900 });
  };

  test('Required permissions, connection test, access denied and form help', async ({ page, request }) => {
    await captureSetupSurfaces(page, request, '');
  });

  test('Required permissions, connection test, access denied and form help in the light theme', async ({ page, request }) => {
    const settings = await getSettings(request);
    const initialThemeId = settings.platform_theme?.id ?? await getThemeIdByName(request, 'Filigran Dark');
    await patchSettings(request, settings.id, 'platform_theme', await getThemeIdByName(request, 'Filigran Light'));
    try {
      await captureSetupSurfaces(page, request, '-light');
    } finally {
      await patchSettings(request, settings.id, 'platform_theme', initialThemeId);
    }
  });
});
