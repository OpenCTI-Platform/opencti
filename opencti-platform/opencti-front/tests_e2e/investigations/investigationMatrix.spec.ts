import { expect, test } from '../fixtures/baseFixtures';
import InvestigationDetailsPage, { MATRIX_HIGHLIGHT_BORDER_COLOR } from '../model/investigationDetails.pageModel';
import { addReport, deleteReport } from '../dataForTesting/report.data';
import {
  deleteInvestigation,
  E2E_OTHER_KILL_CHAIN,
  InvestigationMatrixSeed,
  seedInvestigationMatrix,
  seedInvestigationWithoutAttackPatterns,
} from '../dataForTesting/investigationMatrix.data';

const INVESTIGATION_URL = '/dashboard/workspaces/investigations';

const ALPHA = 'T9001 - E2E Alpha';
const BETA = 'T9002 - E2E Beta';
const UNRELATED = 'T9004 - E2E Unrelated';

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
});
