import fs from 'node:fs';
import { expect, test } from '../fixtures/baseFixtures';
import InvestigationDetailsPage, { MATRIX_HIGHLIGHT_BORDER_COLOR } from '../model/investigationDetails.pageModel';
import { deleteInvestigation, E2E_WIDE_KILL_CHAIN, InvestigationMatrixSeed, seedInvestigationMatrix } from '../dataForTesting/investigationMatrix.data';
import { heatFill, HEAT_STOPS } from '../../src/private/components/workspaces/investigations/matrix/heatScale';
import { getMatrixConfig } from '../../src/private/components/techniques/attack_patterns/attack_patterns_matrix/attackPatternsMatrixConfig';

/*
 * End-to-end coverage of the investigation tactics matrix, kept to what only a real browser and a real platform prove:
 * the data the matrix queries (including the `object` relationship of a report), the colour tokens resolving against the
 * real design-system stylesheet, the graph staying mounted behind the matrix, the "only used" toggle and the unplaced
 * note wired to the real matrix, the backend filters of the security posture, the layout of the exported image, and the
 * shared matrix component on a report page. The rendering rules (decorations, tooltips, accessible names, toggle labels,
 * empty states) are covered by the unit tests next to the components.
 */

const INVESTIGATION_URL = '/dashboard/workspaces/investigations';

const ALPHA = 'T9001 - E2E Alpha';
const BETA = 'T9002 - E2E Beta';
const GAMMA = 'T9003 - E2E Gamma';
const UNRELATED = 'T9004 - E2E Unrelated';

// Tooltip titles of the security posture marks, which MUI also sets as the icons' aria-label.
const SHOULD_COVER = 'Security posture should cover the threat';
const DOES_NOT_COVER = 'Security posture does not cover the threat';
// The seed scores T9001 = 3 (A, B and the report) and T9002 = 1 (A): the scale is 1 to 3, T9001 on the last stop, T9002 on the first.
const LAST_STOP = 4;
const FIRST_STOP = 0;
// What an undefined CSS variable resolves to in a background. A token missing from the design-system
// stylesheet resolves to this on both sides of a `toHaveCSS` against `resolveColor`, so it is checked apart.
const TRANSPARENT = 'rgba(0, 0, 0, 0)';
// The label of a filled cell: --black-1000.
const HEAT_LABEL_COLOR = 'rgb(0, 0, 0)';

// A PNG starts with an 8-byte signature, then the IHDR chunk: 4 bytes of length, 4 of type, then the width as a 32-bit big-endian integer.
const PNG_WIDTH_OFFSET = 16;
// A viewport narrower than the matrix: a capture of the visible box would crop the columns that do not fit.
const NARROW_VIEWPORT = { width: 800, height: 900 };

test.describe('Investigation tactics matrix', { tag: ['@ce'] }, () => {
  const investigationIds: string[] = [];

  test.afterEach(async ({ request }) => {
    // The seeded knowledge is upserted by standard id and stays. Investigations are one per test.
    while (investigationIds.length > 0) {
      const id = investigationIds.pop();
      if (id) await deleteInvestigation(request, id);
    }
  });

  const seed = async (request: Parameters<typeof seedInvestigationMatrix>[0]): Promise<InvestigationMatrixSeed> => {
    const seeded = await seedInvestigationMatrix(request);
    investigationIds.push(seeded.investigationId);
    return seeded;
  };

  test('Switch to the matrix view, turn the heatmap on and go back to the graph', async ({ page, request }) => {
    const { investigationId } = await seed(request);
    const investigationPage = new InvestigationDetailsPage(page);

    await page.goto(`${INVESTIGATION_URL}/${investigationId}`);
    await expect(investigationPage.getGraphViewLink()).toHaveAttribute('aria-checked', 'true');
    await investigationPage.goToMatrix();
    await expect(page).toHaveURL(new RegExp(`${investigationId}/matrix$`));
    await expect(investigationPage.getMatrixViewLink()).toHaveAttribute('aria-checked', 'true');

    // The techniques of the investigation are highlighted, a platform technique outside it is not.
    await expect(investigationPage.getMatrixCell(ALPHA)).toHaveCSS('border-top-color', MATRIX_HIGHLIGHT_BORDER_COLOR);
    await expect(investigationPage.getMatrixCell(BETA)).toHaveCSS('border-top-color', MATRIX_HIGHLIGHT_BORDER_COLOR);
    await expect(investigationPage.getMatrixCell(UNRELATED)).toBeVisible();
    await expect(investigationPage.getMatrixCell(UNRELATED)).not.toHaveCSS('border-top-color', MATRIX_HIGHLIGHT_BORDER_COLOR);
    await expect(investigationPage.getLegend()).toBeHidden();
    // The report counts: the `object` relationship comes back from the real investigation query.
    await expect(page.getByRole('button', { name: `${ALPHA}, linked to 3 entities`, exact: true })).toBeVisible();

    // The "only used" toggle hides the platform technique outside the investigation, and brings it back.
    await investigationPage.getMatrix().getByRole('button', { name: 'Display only used techniques' }).click();
    await expect(investigationPage.getMatrixCell(UNRELATED)).toBeHidden();
    await expect(investigationPage.getMatrixCell(ALPHA)).toBeVisible();
    await investigationPage.getMatrix().getByRole('button', { name: 'Display the whole matrix' }).click();
    await expect(investigationPage.getMatrixCell(UNRELATED)).toBeVisible();

    await investigationPage.toggleHeatmap();

    // T9001 is used by A, B and the report: the last stop. T9002 is used by A only: the first.
    const lastStopFill = await investigationPage.resolveColor(heatFill(LAST_STOP), 'backgroundColor');
    const firstStopFill = await investigationPage.resolveColor(heatFill(FIRST_STOP), 'backgroundColor');
    await expect(investigationPage.getMatrixCell(ALPHA)).toHaveCSS('background-color', lastStopFill);
    await expect(investigationPage.getMatrixCell(BETA)).toHaveCSS('background-color', firstStopFill);
    await expect(investigationPage.getLegend()).toHaveAttribute('aria-label', 'Technique usage scale, 1 to 3');

    // Every colour token resolves: none of the fills, the legend stops, the label or the badge is left transparent.
    expect(firstStopFill).not.toBe(TRANSPARENT);
    expect(lastStopFill).not.toBe(TRANSPARENT);
    await Promise.all(HEAT_STOPS.map((_, stop) => (
      expect(investigationPage.getLegendSwatch(stop)).not.toHaveCSS('background-color', TRANSPARENT)
    )));
    await expect(investigationPage.getCellLabel(ALPHA)).toHaveCSS('color', HEAT_LABEL_COLOR);
    const badgeBackground = await investigationPage.resolveColor(getMatrixConfig('investigation', false).badgeColors?.color ?? '', 'backgroundColor');
    expect(badgeBackground).not.toBe(TRANSPARENT);
    await expect(investigationPage.getBadgeOfCell(GAMMA)).toHaveCSS('background-color', badgeBackground);

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

  test('The security posture marks the techniques it should cover', async ({ page, request }) => {
    const { investigationId } = await seed(request);
    const investigationPage = new InvestigationDetailsPage(page);

    await page.goto(`${INVESTIGATION_URL}/${investigationId}/matrix`);
    await expect(investigationPage.getMatrixCell(ALPHA)).toBeVisible();
    // No platform selected: no mark at all.
    await expect(investigationPage.getMatrix().getByLabel(SHOULD_COVER, { exact: true })).toHaveCount(0);
    await expect(investigationPage.getMatrix().getByLabel(DOES_NOT_COVER, { exact: true })).toHaveCount(0);

    await investigationPage.selectSecurityPlatform('E2E Matrix platform');
    // The platform should cover T9001 only: a tick on T9001, a cross on T9002.
    await expect(investigationPage.getMatrixCell(ALPHA).getByLabel(SHOULD_COVER, { exact: true })).toBeVisible();
    await expect(investigationPage.getMatrixCell(BETA).getByLabel(DOES_NOT_COVER, { exact: true })).toBeVisible();
  });

  test('The header exports the whole matrix to an image', async ({ page, request }) => {
    const { investigationId, investigationName } = await seed(request);
    const investigationPage = new InvestigationDetailsPage(page);
    await page.setViewportSize(NARROW_VIEWPORT);

    await page.goto(`${INVESTIGATION_URL}/${investigationId}/matrix`);
    await expect(investigationPage.getMatrixCell(ALPHA)).toBeVisible();
    await investigationPage.getKillChainSelect().click();
    await investigationPage.getKillChainOption(E2E_WIDE_KILL_CHAIN).click();
    // T9004 also sits in the default kill chain: wait for T9001, which the wide one does not hold, to leave first.
    await expect(investigationPage.getMatrixCell(ALPHA)).toBeHidden();
    await expect(investigationPage.getMatrixCell(UNRELATED).first()).toBeVisible();
    // The wide kill chain holds none of the attack patterns of the investigation: the note lists them.
    await expect(investigationPage.getMatrix().getByText(/attack patterns in this investigation aren't shown in this kill chain/)).toBeVisible();
    const matrixWidth = await investigationPage.getMatrixScrollWidth();
    // The wide kill chain really overflows the viewport.
    expect(matrixWidth).toBeGreaterThan(NARROW_VIEWPORT.width);
    const styleBeforeExport = await investigationPage.getMatrix().getAttribute('style');

    await investigationPage.getExportToImageButton().click();
    const downloadPromise = page.waitForEvent('download');
    await investigationPage.getExportImageMenuItem('Light').click();
    const download = await downloadPromise;

    expect(download.suggestedFilename()).toBe(`${investigationName} - Tactics matrix.png`);
    const imageWidth = fs.readFileSync(await download.path()).readUInt32BE(PNG_WIDTH_OFFSET);
    // No column is cropped: the image is at least as wide as the whole matrix.
    expect(imageWidth).toBeGreaterThanOrEqual(matrixWidth);

    // The capture leaves the matrix as it was.
    await expect(investigationPage.getMatrix()).toHaveAttribute('style', styleBeforeExport ?? '');
    expect(await investigationPage.getMatrixScrollWidth()).toBe(matrixWidth);
  });

  // The matrix component is shared: this guards the existing container pages against the investigation changes.
  test('The matrix of a report keeps its plain labels and its Add action', async ({ page, request }) => {
    const { reportId } = await seed(request);

    await page.goto(`/dashboard/analyses/reports/${reportId}/knowledge/matrix`);
    const cell = page.getByText('E2E Alpha', { exact: true });
    await expect(cell).toBeVisible();
    // No technique ID prefix outside of investigations.
    await expect(page.getByText(ALPHA, { exact: true })).toHaveCount(0);

    await cell.click();
    await expect(page.getByRole('menuitem', { name: 'View' })).toBeVisible();
    await expect(page.getByRole('menuitem', { name: 'Add' })).toBeVisible();
  });
});
