import { APIRequestContext, Locator, Page } from '@playwright/test';
import { expect, test } from '../fixtures/baseFixtures';
import HuntsPage from '../model/hunts.pageModel';
import TextFieldPageModel from '../model/field/TextField.pageModel';
import { deleteHunt } from '../dataForTesting/hunt.data';
import { graphqlRequest } from '../dataForTesting/graphql.data';
import { getSettings, getThemeIdByName, patchSettings } from '../dataForTesting/settings.data';

const GENERATED_RULE = `title: Office application spawning encoded PowerShell
status: experimental
logsource:
  product: windows
  category: process_creation
detection:
  selection_parent:
    ParentImage|endswith:
      - '\\WINWORD.EXE'
      - '\\EXCEL.EXE'
  selection_child:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: ' -enc '
  condition: all of selection_*
level: high
tags:
  - attack.execution
  - attack.t1059.001`;
const RATIONALE = 'APT28 delivers Office documents whose macros start an encoded PowerShell command.';
const HYPOTHESIS = 'If APT28 is active, Office applications start PowerShell with an encoded command on our endpoints';

/**
 * The hunt drawers: Learn more in the drawer header, the Enterprise Edition chips right after their label, the actions
 * of the Sigma rule and of the native queries in their label row, and Generate with AI on the Sigma rule. A test
 * platform reaches neither XTM One nor an Enterprise Edition licence: for those states the responses that read them
 * are completed (the licence, the XTM One availability) and the generation answers a sample rule. The screenshots are
 * saved with the test results for the user documentation (`docs/docs/usage/assets/hunt-drawer-*.png`).
 */
test.describe('Hunt drawers', { tag: ['@hunt', '@mutation'] }, () => {
  test.describe.configure({ mode: 'serial' });
  test.use({ viewport: { width: 1440, height: 1400 }, deviceScaleFactor: 2 });
  const margin = 12;

  /** Screenshot of the area covering every given surface. */
  const capture = async (page: Page, name: string, surfaces: Locator[]) => {
    for (const surface of surfaces) {
      await expect(surface).toBeVisible();
    }
    await surfaces[surfaces.length - 1].scrollIntoViewIfNeeded();
    const boxes = [];
    for (const surface of surfaces) {
      boxes.push(await surface.boundingBox());
    }
    const known = boxes.filter((box): box is NonNullable<typeof box> => !!box);
    const viewport = page.viewportSize() ?? { width: 1440, height: 1400 };
    const x = Math.max(0, Math.min(...known.map((box) => box.x)) - margin);
    const y = Math.max(0, Math.min(...known.map((box) => box.y)) - margin);
    const right = Math.min(viewport.width, Math.max(...known.map((box) => box.x + box.width)) + margin);
    const bottom = Math.min(viewport.height, Math.max(...known.map((box) => box.y + box.height)) + margin);
    await page.screenshot({ path: test.info().outputPath(name), animations: 'disabled', clip: { x, y, width: right - x, height: bottom - y } });
  };

  const isOperation = (body: { id?: string; query?: string } | null, kind: 'query' | 'mutation', name: string) => body?.id === name
    || (typeof body?.query === 'string' && new RegExp(`\\b${kind} ${name}\\b`).test(body.query));

  /** The licence and the XTM One availability the platform would report with them. */
  const withPlatform = async (page: Page, { enterpriseEdition, xtmOne }: { enterpriseEdition: boolean; xtmOne: boolean }) => {
    await page.route('**/chatbot/config', async (route) => {
      const response = await route.fetch();
      const json = response.ok() ? await response.json() : {};
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ ...json, xtm_one_configured: xtmOne }) });
    });
    await page.route('**/graphql', async (route) => {
      const body = route.request().postDataJSON();
      if (isOperation(body, 'query', 'RootPrivateQuery')) {
        const response = await route.fetch();
        const json = await response.json();
        if (json?.data?.settings?.platform_enterprise_edition) {
          json.data.settings.platform_enterprise_edition.license_validated = enterpriseEdition;
        }
        await route.fulfill({ response, json });
      } else if (isOperation(body, 'mutation', 'HuntSigmaRuleFieldGenerateMutation')) {
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ data: { huntSigmaGenerate: { sigma_rule: GENERATED_RULE, rationale: RATIONALE } } }) });
      } else {
        await route.fallback();
      }
    });
  };

  const openCreationDrawer = async (page: Page) => {
    const huntsPage = new HuntsPage(page);
    await huntsPage.goto();
    await huntsPage.openCreateForm();
    const form = page.getByTestId('hunt-creation-form');
    await expect(form).toBeVisible();
    return form;
  };

  const drawerHeader = (page: Page) => page.getByTestId('hunt-creation-learn-more').locator('xpath=ancestor::div[contains(@class, "MuiStack-root")][2]');

  const sigmaEditor = (page: Page) => page.getByTestId('hunt-sigma-editor').locator('textarea');

  const captureDrawer = async (page: Page, suffix: string) => {
    // Community Edition, as a test platform runs: the EE chips follow their label
    const form = await openCreationDrawer(page);
    // Learn more sits in the drawer header, left of the close button, no longer above the first field
    await expect(form.getByTestId('hunt-creation-learn-more')).toHaveCount(0);
    await capture(page, `hunt-drawer-header${suffix}.png`, [drawerHeader(page), new TextFieldPageModel(page, 'Name', 'text', form).get()]);
    await capture(page, `hunt-drawer-logic${suffix}.png`, [page.getByTestId('hunt-sigma-editor'), page.getByTestId('hunt-native-queries')]);
    await expect(page.getByTestId('hunt-native-query-add')).toBeVisible();
    const schedule = page.getByTestId('hunt-schedule-field');
    const pir = form.getByText('Activate when a PIR flags one of its targets');
    await capture(page, `hunt-drawer-ee-chips${suffix}.png`, [schedule, pir]);
  };

  const captureGeneration = async (page: Page, suffix: string) => {
    await withPlatform(page, { enterpriseEdition: true, xtmOne: true });
    const form = await openCreationDrawer(page);
    await new TextFieldPageModel(page, 'Name', 'text', form).fill('APT28 encoded PowerShell from Office');
    // The hypothesis is the first Markdown field of the form, before the description
    await form.getByTestId('text-area').first().fill(HYPOTHESIS);
    await expect(page.getByTestId('hunt-sigma-generate')).toBeEnabled();
    await page.getByTestId('hunt-sigma-generate').click();
    await expect(sigmaEditor(page)).toHaveValue(GENERATED_RULE);
    await expect(page.getByTestId('hunt-sigma-generated')).toContainText(RATIONALE);
    await expect(page.getByTestId('hunt-sigma-validation')).toContainText('Valid Sigma rule');
    await capture(page, `hunt-drawer-sigma-generated${suffix}.png`, [page.getByTestId('hunt-sigma-editor'), page.getByTestId('hunt-sigma-generated'), page.getByTestId('hunt-sigma-validation')]);
    await page.getByTestId('hunt-sigma-generate-undo').click();
    await expect(sigmaEditor(page)).toHaveValue('');
  };

  const withTheme = async (request: APIRequestContext, theme: string, run: () => Promise<void>) => {
    const settings = await getSettings(request);
    const initialThemeId = settings.platform_theme?.id ?? await getThemeIdByName(request, 'Filigran Dark');
    await patchSettings(request, settings.id, 'platform_theme', await getThemeIdByName(request, theme));
    try {
      await run();
    } finally {
      await patchSettings(request, settings.id, 'platform_theme', initialThemeId);
    }
  };

  test('Learn more in the header, field actions in their label row, EE chips after their label', async ({ page }) => {
    await captureDrawer(page, '');
  });

  test('Generate the Sigma rule with XTM One, then undo it', async ({ page }) => {
    await captureGeneration(page, '');
  });

  test('Generate with AI is disabled, with its reason, when XTM One is not configured', async ({ page }) => {
    await withPlatform(page, { enterpriseEdition: true, xtmOne: false });
    await openCreationDrawer(page);
    await expect(page.getByTestId('hunt-sigma-generate')).toBeDisabled();
    await expect(page.getByTestId('hunt-sigma-generate-reason')).toHaveText('XTM One is not configured on this platform');
    await capture(page, 'hunt-drawer-sigma-unavailable.png', [page.getByTestId('hunt-sigma-editor')]);
  });

  test('Generate the Sigma rule of a saved hunt from its Logic tab', async ({ page, request }) => {
    const created = await graphqlRequest<{ huntAdd: { id: string } }>(request, `
      mutation {
        huntAdd(input: { name: "E2E APT28 encoded PowerShell", hypothesis: ${JSON.stringify(HYPOTHESIS)}, hunt_status: draft }) { id }
      }
    `, 'Create a hunt without a Sigma rule');
    try {
      await withPlatform(page, { enterpriseEdition: true, xtmOne: true });
      await page.goto(`/dashboard/defense/hunts/${created.huntAdd.id}/logic`);
      await page.getByTestId('hunt-sigma-generate').click();
      await expect(page.getByTestId('hunt-logic-sigma').locator('textarea')).toHaveValue(GENERATED_RULE);
      await expect(page.getByTestId('hunt-logic-save-and-preview')).toBeVisible();
      await capture(page, 'hunt-drawer-logic-tab-generated.png', [page.getByTestId('hunt-logic-sigma'), page.getByTestId('hunt-sigma-generated')]);
    } finally {
      await deleteHunt(request, created.huntAdd.id);
    }
  });

  test('Hunt drawers in the light theme', async ({ page, request }) => {
    await withTheme(request, 'Filigran Light', async () => {
      await captureDrawer(page, '-light');
      await page.unrouteAll({ behavior: 'ignoreErrors' });
      await captureGeneration(page, '-light');
    });
  });
});
