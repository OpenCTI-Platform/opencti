import fs from 'node:fs';
import { expect, test } from '../fixtures/baseFixtures';
import InvestigationDetailsPage, { MATRIX_HIGHLIGHT_BORDER_COLOR } from '../model/investigationDetails.pageModel';
import { addReport, deleteReport } from '../dataForTesting/report.data';
import {
  deleteInvestigation,
  E2E_OTHER_KILL_CHAIN,
  E2E_WIDE_KILL_CHAIN,
  InvestigationMatrixSeed,
  seedInvestigationMatrix,
  seedInvestigationWithoutAttackPatterns,
  seedInvestigationWithoutScores,
} from '../dataForTesting/investigationMatrix.data';
import { heatBorder, heatFill, HEAT_STOPS } from '../../src/private/components/workspaces/investigations/matrix/heatScale';
import { getMatrixConfig } from '../../src/private/components/techniques/attack_patterns/attack_patterns_matrix/attackPatternsMatrixConfig';

const INVESTIGATION_URL = '/dashboard/workspaces/investigations';

const ALPHA = 'T9001 - E2E Alpha';
const BETA = 'T9002 - E2E Beta';
const GAMMA = 'T9003 - E2E Gamma';
const GAMMA_SUB = 'T9003.001 - E2E Gamma sub';
const UNRELATED = 'T9004 - E2E Unrelated';

const HEATMAP_TOGGLE_TOOLTIP = 'Displays heat map of attack pattern use';
const HEATMAP_DISABLED_TOOLTIP = 'No attack pattern is linked to an entity in this investigation';
// The seed scores T9001 = 2 (A and B) and T9002 = 1 (A): the scale is 1 to 2, T9001 on the last stop, T9002 on the first.
const LAST_STOP = 4;
const FIRST_STOP = 0;
// The neutral outline of a technique of the investigation that nobody uses.
const NEUTRAL_OUTLINE = 'var(--border-elevation-default)';
// What an undefined CSS variable resolves to in a background. A token missing from the design-system
// stylesheet resolves to this on both sides of a `toHaveCSS` against `resolveColor`, so it is checked apart.
const TRANSPARENT = 'rgba(0, 0, 0, 0)';
// The label of a filled cell: --black-1000.
const HEAT_LABEL_COLOR = 'rgb(0, 0, 0)';

// A PNG starts with an 8-byte signature, then the IHDR chunk: 4 bytes of length, 4 of type, then the width as a 32-bit big-endian integer.
const PNG_WIDTH_OFFSET = 16;

test.describe('Investigation tactics matrix', { tag: ['@ce'] }, () => {
  const investigationIds: string[] = [];

  test.afterEach(async ({ request }) => {
    // The seeded knowledge is upserted by standard id and stays. Investigations are one per test.
    while (investigationIds.length > 0) {
      const id = investigationIds.pop();
      if (id) await deleteInvestigation(request, id);
    }
  });

  const seed = async (
    request: Parameters<typeof seedInvestigationMatrix>[0],
    options?: Parameters<typeof seedInvestigationMatrix>[1],
  ): Promise<InvestigationMatrixSeed> => {
    const seeded = await seedInvestigationMatrix(request, options);
    investigationIds.push(seeded.investigationId);
    return seeded;
  };

  test('Switch to the matrix view and see the techniques of the investigation highlighted', async ({ page, request }) => {
    const { investigationId } = await seed(request);
    const investigationPage = new InvestigationDetailsPage(page);

    await page.goto(`${INVESTIGATION_URL}/${investigationId}`);
    await expect(investigationPage.getGraphViewLink()).toBeVisible();
    await expect(investigationPage.getMatrixViewLink()).toBeVisible();
    await expect(investigationPage.getGraphViewLink()).toHaveAttribute('aria-checked', 'true');

    await investigationPage.goToMatrix();
    await expect(page).toHaveURL(new RegExp(`${investigationId}/matrix$`));
    await expect(investigationPage.getMatrixViewLink()).toHaveAttribute('aria-checked', 'true');
    await expect(investigationPage.getMatrixCell(ALPHA)).toBeVisible();
    await expect(investigationPage.getMatrixCell(ALPHA)).toHaveCSS('border-top-color', MATRIX_HIGHLIGHT_BORDER_COLOR);
  });

  test('Only the techniques of the investigation are highlighted', async ({ page, request }) => {
    const { investigationId } = await seed(request);
    const investigationPage = new InvestigationDetailsPage(page);

    await page.goto(`${INVESTIGATION_URL}/${investigationId}/matrix`);
    await expect(investigationPage.getMatrixCell(ALPHA)).toHaveCSS('border-top-color', MATRIX_HIGHLIGHT_BORDER_COLOR);
    await expect(investigationPage.getMatrixCell(BETA)).toHaveCSS('border-top-color', MATRIX_HIGHLIGHT_BORDER_COLOR);
    // A platform technique that is not part of the investigation keeps the neutral style.
    await expect(investigationPage.getMatrixCell(UNRELATED)).toBeVisible();
    await expect(investigationPage.getMatrixCell(UNRELATED)).not.toHaveCSS('border-top-color', MATRIX_HIGHLIGHT_BORDER_COLOR);
  });

  test('Going back to the graph does not reload the investigation objects', async ({ page, request }) => {
    const { investigationId } = await seed(request);
    const investigationPage = new InvestigationDetailsPage(page);

    await page.goto(`${INVESTIGATION_URL}/${investigationId}`);
    await investigationPage.goToMatrix();
    await expect(investigationPage.getMatrixCell(ALPHA)).toBeVisible();

    // The graph stays mounted behind the matrix: switching back must not fetch the objects again.
    const objectsRequest = page.waitForRequest(
      (req) => req.url().includes('/graphql') && (req.postData() ?? '').includes('InvestigationGraphObjectsQuery'),
      { timeout: 2000 },
    );
    const noRequest = expect(objectsRequest).rejects.toThrow(/Timeout/);
    await investigationPage.goToGraph();
    await expect(page).toHaveURL(new RegExp(`${investigationId}$`));
    await noRequest;
  });

  test('An investigation without attack patterns shows the empty text', async ({ page, request }) => {
    const investigationId = await seedInvestigationWithoutAttackPatterns(request);
    investigationIds.push(investigationId);
    const investigationPage = new InvestigationDetailsPage(page);

    await page.goto(`${INVESTIGATION_URL}/${investigationId}`);
    await investigationPage.goToMatrix();
    await expect(investigationPage.getEmptyMatrixText()).toBeVisible();
  });

  test('The "only used" toggle hides the techniques that are not in the investigation', async ({ page, request }) => {
    const { investigationId } = await seed(request);
    const investigationPage = new InvestigationDetailsPage(page);

    await page.goto(`${INVESTIGATION_URL}/${investigationId}/matrix`);
    await expect(investigationPage.getMatrixCell(UNRELATED)).toBeVisible();

    await investigationPage.getOnlyUsedToggle().click();
    await expect(investigationPage.getMatrixCell(UNRELATED)).toBeHidden();
    await expect(investigationPage.getMatrixCell(ALPHA)).toBeVisible();
    await expect(investigationPage.getMatrixCell(BETA)).toBeVisible();

    await investigationPage.getOnlyUsedToggle().click();
    await expect(investigationPage.getMatrixCell(UNRELATED)).toBeVisible();
  });

  test('The security posture marks the techniques it should cover', async ({ page, request }) => {
    const { investigationId } = await seed(request);
    const investigationPage = new InvestigationDetailsPage(page);

    await page.goto(`${INVESTIGATION_URL}/${investigationId}/matrix`);
    await expect(investigationPage.getMatrixCell(ALPHA)).toBeVisible();
    // No platform selected: no mark at all.
    await expect(investigationPage.getMatrix().getByTestId('CheckOutlinedIcon')).toHaveCount(0);

    await investigationPage.selectSecurityPlatform('E2E Matrix platform');
    // The platform should cover T9001 only: a tick on T9001, a cross on T9002.
    await expect(investigationPage.getMatrixCell(ALPHA).getByTestId('CheckOutlinedIcon')).toBeVisible();
    await expect(investigationPage.getMatrixCell(BETA).getByTestId('CloseOutlinedIcon')).toBeVisible();
  });

  test('Switching the kill chain lists the attack patterns that cannot be placed', async ({ page, request }) => {
    const { investigationId } = await seed(request);
    const investigationPage = new InvestigationDetailsPage(page);

    await page.goto(`${INVESTIGATION_URL}/${investigationId}/matrix`);
    await expect(investigationPage.getMatrixCell(ALPHA)).toBeVisible();
    // Every attack pattern of the investigation sits in the default kill chain.
    await expect(investigationPage.getUnplacedNote()).toBeHidden();

    await investigationPage.getKillChainSelect().click();
    await investigationPage.getKillChainOption(E2E_OTHER_KILL_CHAIN).click();
    await expect(investigationPage.getUnplacedNote()).toBeVisible();
    await expect(investigationPage.getMatrixCell(ALPHA)).toBeHidden();
  });

  test('The matrix of a report keeps its plain labels and its Add action', async ({ page, request }) => {
    const { attackPatterns } = await seed(request);
    const reportResponse = await addReport(request, {
      name: `E2E matrix report ${Date.now()}`,
      objects: [attackPatterns.T9001],
    });
    const reportId = (await reportResponse.json()).data.reportAdd.id;

    try {
      await page.goto(`/dashboard/analyses/reports/${reportId}/knowledge/matrix`);
      const cell = page.getByText('E2E Alpha', { exact: true });
      await expect(cell).toBeVisible();
      // No technique ID prefix outside of investigations.
      await expect(page.getByText(ALPHA, { exact: true })).toHaveCount(0);

      await cell.click();
      await expect(page.getByRole('menuitem', { name: 'View' })).toBeVisible();
      await expect(page.getByRole('menuitem', { name: 'Add' })).toBeVisible();
    } finally {
      await deleteReport(request, reportId);
    }
  });

  test.describe('Heatmap', () => {
    test('The heatmap colours the used techniques and shows its legend', async ({ page, request }) => {
      const { investigationId } = await seed(request);
      const investigationPage = new InvestigationDetailsPage(page);

      await page.goto(`${INVESTIGATION_URL}/${investigationId}/matrix`);
      await expect(investigationPage.getMatrixCell(ALPHA)).toBeVisible();
      // Off by default: no legend.
      await expect(investigationPage.getLegend()).toBeHidden();

      await investigationPage.toggleHeatmap();

      // T9001 is used by A and B: the last stop. T9002 is used by A only: the first.
      const lastStopFill = await investigationPage.resolveColor(heatFill(LAST_STOP), 'backgroundColor');
      const firstStopFill = await investigationPage.resolveColor(heatFill(FIRST_STOP), 'backgroundColor');
      await expect(investigationPage.getMatrixCell(ALPHA)).toHaveCSS('background-color', lastStopFill);
      await expect(investigationPage.getMatrixCell(BETA)).toHaveCSS('background-color', firstStopFill);
      await expect(investigationPage.getLegend()).toBeVisible();
      await expect(investigationPage.getLegend()).toHaveAttribute('aria-label', 'Technique usage scale, 1 to 2');
      await expect(investigationPage.getLegend()).toContainText('Technique usage (low → high)');
      // A technique the investigation does not hold is not decorated.
      await expect(investigationPage.getMatrixCell(UNRELATED)).not.toHaveCSS('background-color', firstStopFill);

      // Every colour token resolves: none of the fills, the legend stops, the label or the badge is left transparent.
      expect(firstStopFill).not.toBe(TRANSPARENT);
      expect(lastStopFill).not.toBe(TRANSPARENT);
      await Promise.all(HEAT_STOPS.map((_, stop) => (
        expect(investigationPage.getLegendSwatch(stop)).not.toHaveCSS('background-color', TRANSPARENT)
      )));
      await expect(investigationPage.getCellLabel(ALPHA)).toHaveCSS('color', HEAT_LABEL_COLOR);
      await expect(investigationPage.getCellLabel(BETA)).toHaveCSS('color', HEAT_LABEL_COLOR);
      const badgeBackground = await investigationPage.resolveColor(getMatrixConfig('investigation', false).badgeColors?.color ?? '', 'backgroundColor');
      expect(badgeBackground).not.toBe(TRANSPARENT);
      await expect(investigationPage.getBadgeOfCell(GAMMA)).toHaveCSS('background-color', badgeBackground);
    });

    test('The accessible name of a used technique counts its linked entities', async ({ page, request }) => {
      const { investigationId } = await seed(request);
      const investigationPage = new InvestigationDetailsPage(page);

      await page.goto(`${INVESTIGATION_URL}/${investigationId}/matrix`);
      await expect(page.getByRole('button', { name: `${ALPHA}, linked to 2 entities`, exact: true })).toBeVisible();
      await expect(page.getByRole('button', { name: `${BETA}, linked to 1 entity`, exact: true })).toBeVisible();
      // A technique outside the investigation keeps its plain label.
      await expect(investigationPage.getMatrixCell(UNRELATED)).toHaveAccessibleName(UNRELATED);
    });

    test('Hovering a technique lists the entities linked to it', async ({ page, request }) => {
      const { investigationId } = await seed(request);
      const investigationPage = new InvestigationDetailsPage(page);

      await page.goto(`${INVESTIGATION_URL}/${investigationId}/matrix`);
      await investigationPage.toggleHeatmap();
      await investigationPage.getMatrixCell(ALPHA).hover();

      const tooltip = investigationPage.getTooltip().filter({ hasText: 'Linked entities (2)' });
      await expect(tooltip).toBeVisible();
      // Sorted by name, each entity once.
      await expect(tooltip).toContainText('E2E Matrix A, E2E Matrix B');
    });

    test('A technique of the investigation that nobody uses gets the neutral outline', async ({ page, request }) => {
      const { investigationId } = await seed(request);
      const investigationPage = new InvestigationDetailsPage(page);

      await page.goto(`${INVESTIGATION_URL}/${investigationId}/matrix`);
      await investigationPage.toggleHeatmap();

      // T9003 is in the investigation with no relationship to an entity: no fill, only the outline.
      const outline = await investigationPage.resolveColor(NEUTRAL_OUTLINE, 'color');
      const firstStopFill = await investigationPage.resolveColor(heatFill(FIRST_STOP), 'backgroundColor');
      await expect(investigationPage.getAccordionOfCell(GAMMA)).toHaveCSS('border-top-color', outline);
      await expect(investigationPage.getMatrixCell(GAMMA)).not.toHaveCSS('background-color', firstStopFill);
      // A used technique is filled, and not outlined.
      await expect(investigationPage.getMatrixCell(ALPHA)).not.toHaveCSS('border-top-color', outline);
    });

    test('A parent technique takes the border colour of its used sub-technique', async ({ page, request }) => {
      // A uses T9003.001 only: T9003 itself is not used.
      const { investigationId } = await seed(request, { withSubtechniqueUse: true });
      const investigationPage = new InvestigationDetailsPage(page);

      await page.goto(`${INVESTIGATION_URL}/${investigationId}/matrix`);
      await investigationPage.toggleHeatmap();
      await investigationPage.getExpandButton(GAMMA).click();

      // The sub-technique scores 1: the first stop, as its fill.
      const firstStopFill = await investigationPage.resolveColor(heatFill(FIRST_STOP), 'backgroundColor');
      await expect(investigationPage.getMatrixCell(GAMMA_SUB)).toHaveCSS('background-color', firstStopFill);
      // The parent is not filled: its border carries the stop of its sub-technique.
      await expect(investigationPage.getAccordionOfCell(GAMMA))
        .toHaveCSS('border-top-color', await investigationPage.resolveColor(heatBorder(FIRST_STOP), 'color'));
      await expect(investigationPage.getMatrixCell(GAMMA)).not.toHaveCSS('background-color', firstStopFill);

      // Hovering the parent lists the entities linked to its sub-techniques.
      await investigationPage.getMatrixCell(GAMMA).hover();
      await expect(investigationPage.getTooltip().filter({ hasText: 'Linked entities (1)' })).toContainText('E2E Matrix A');
    });

    test('Switching the heatmap off removes the legend and the heat', async ({ page, request }) => {
      const { investigationId } = await seed(request);
      const investigationPage = new InvestigationDetailsPage(page);

      await page.goto(`${INVESTIGATION_URL}/${investigationId}/matrix`);
      await investigationPage.toggleHeatmap();
      await expect(investigationPage.getLegend()).toBeVisible();
      const lastStopFill = await investigationPage.resolveColor(heatFill(LAST_STOP), 'backgroundColor');
      await expect(investigationPage.getMatrixCell(ALPHA)).toHaveCSS('background-color', lastStopFill);

      await investigationPage.toggleHeatmap();
      await expect(investigationPage.getLegend()).toBeHidden();
      await expect(investigationPage.getMatrixCell(ALPHA)).not.toHaveCSS('background-color', lastStopFill);
      // The technique is still highlighted as a technique of the investigation.
      await expect(investigationPage.getMatrixCell(ALPHA)).toHaveCSS('border-top-color', MATRIX_HIGHLIGHT_BORDER_COLOR);
    });

    test('The heatmap toggle explains what it does', async ({ page, request }) => {
      const { investigationId } = await seed(request);
      const investigationPage = new InvestigationDetailsPage(page);

      await page.goto(`${INVESTIGATION_URL}/${investigationId}/matrix`);
      await expect(investigationPage.getHeatmapToggle()).toBeEnabled();
      await investigationPage.getHeatmapToggle().hover();
      await expect(investigationPage.getTooltip().filter({ hasText: HEATMAP_TOGGLE_TOOLTIP })).toBeVisible();
    });

    test('The heatmap toggle is disabled, with its reason, when no technique is used', async ({ page, request }) => {
      const investigationId = await seedInvestigationWithoutScores(request);
      investigationIds.push(investigationId);
      const investigationPage = new InvestigationDetailsPage(page);

      await page.goto(`${INVESTIGATION_URL}/${investigationId}/matrix`);
      // The investigation holds attack patterns, so the matrix is there.
      await expect(investigationPage.getMatrixCell(ALPHA)).toBeVisible();
      await expect(investigationPage.getHeatmapToggle()).toBeDisabled();
      await expect(investigationPage.getLegend()).toBeHidden();

      // A disabled button takes no pointer event: the tooltip belongs to its focusable wrapper.
      await investigationPage.getHeatmapToggleWrapper().hover();
      await expect(investigationPage.getTooltip().filter({ hasText: HEATMAP_DISABLED_TOOLTIP })).toBeVisible();
    });

    test('The heatmap toggle is disabled in an investigation without attack patterns', async ({ page, request }) => {
      const investigationId = await seedInvestigationWithoutAttackPatterns(request);
      investigationIds.push(investigationId);
      const investigationPage = new InvestigationDetailsPage(page);

      await page.goto(`${INVESTIGATION_URL}/${investigationId}/matrix`);
      await expect(investigationPage.getEmptyMatrixText()).toBeVisible();
      await expect(investigationPage.getHeatmapToggle()).toBeDisabled();
    });
  });

  test.describe('Export', () => {
    // A viewport narrower than the matrix: a capture of the visible box would crop the columns that do not fit.
    const NARROW_VIEWPORT = { width: 800, height: 900 };

    for (const theme of ['Light', 'Dark'] as const) {
      test(`The header exports the whole matrix to an image, ${theme} theme`, async ({ page, request }) => {
        const { investigationId, investigationName } = await seed(request);
        const investigationPage = new InvestigationDetailsPage(page);
        await page.setViewportSize(NARROW_VIEWPORT);

        await page.goto(`${INVESTIGATION_URL}/${investigationId}/matrix`);
        await expect(investigationPage.getMatrixCell(ALPHA)).toBeVisible();
        await investigationPage.getKillChainSelect().click();
        await investigationPage.getKillChainOption(E2E_WIDE_KILL_CHAIN).click();
        await expect(investigationPage.getMatrixCell(UNRELATED).first()).toBeVisible();
        const matrixWidth = await investigationPage.getMatrixScrollWidth();
        // The wide kill chain really overflows the viewport.
        expect(matrixWidth).toBeGreaterThan(NARROW_VIEWPORT.width);
        const styleBeforeExport = await investigationPage.getMatrix().getAttribute('style');

        await investigationPage.getExportToImageButton().click();
        const downloadPromise = page.waitForEvent('download');
        await investigationPage.getExportImageMenuItem(theme).click();
        const download = await downloadPromise;

        expect(download.suggestedFilename()).toBe(`${investigationName} - Tactics matrix.png`);
        const imageWidth = fs.readFileSync(await download.path()).readUInt32BE(PNG_WIDTH_OFFSET);
        // No column is cropped: the image is at least as wide as the whole matrix.
        expect(imageWidth).toBeGreaterThanOrEqual(matrixWidth);

        // The capture leaves the matrix as it was.
        await expect(investigationPage.getMatrix()).toHaveAttribute('style', styleBeforeExport ?? '');
        expect(await investigationPage.getMatrixScrollWidth()).toBe(matrixWidth);
      });
    }

    test('The header exports the matrix to a PDF', async ({ page, request }) => {
      const { investigationId, investigationName } = await seed(request);
      const investigationPage = new InvestigationDetailsPage(page);
      await page.setViewportSize(NARROW_VIEWPORT);

      await page.goto(`${INVESTIGATION_URL}/${investigationId}/matrix`);
      await expect(investigationPage.getMatrixCell(ALPHA)).toBeVisible();

      await investigationPage.getExportToPdfButton().click();
      const downloadPromise = page.waitForEvent('download');
      await investigationPage.getExportPdfMenuItem('Dark').click();
      const download = await downloadPromise;

      expect(download.suggestedFilename()).toBe(`${investigationName} - Tactics matrix.pdf`);
    });
  });
});
