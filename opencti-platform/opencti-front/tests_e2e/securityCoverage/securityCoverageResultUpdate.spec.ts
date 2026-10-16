import { v4 as uuid } from 'uuid';
import { expect, test } from '../fixtures/baseFixtures';
import { addReport, deleteReport } from '../dataForTesting/report.data';
import {
  addAttackPattern,
  addSecurityCoverage,
  addSecurityCoverageResult,
  deleteAttackPattern,
  deleteSecurityCoverage,
  getSecurityCoverageResult,
} from '../dataForTesting/securityCoverage.data';
import SecurityCoverageDetailsPage from '../model/securityCoverageDetails.pageModel';
import SecurityCoverageResultFormPage from '../model/form/securityCoverageResultForm.pageModel';
import { awaitUntilCondition } from '../utils';

/**
 * Content of the test
 * -------------------
 * Create a report with two attack patterns, a security coverage of this report,
 * and a manual result covering the first attack pattern (through the API).
 * Update the manual result: rename it and cover the second attack pattern.
 * Check the first attack pattern, already covered, cannot be selected again.
 * Check the relationships step cannot be reached without a selected entity.
 * Check the result is renamed and covers both attack patterns.
 */
test('Update a manual security coverage result', { tag: ['@securityCoverage', '@mutation'] }, async ({ page, request }) => {
  const securityCoverageDetails = new SecurityCoverageDetailsPage(page);
  const resultForm = new SecurityCoverageResultFormPage(page);

  // region Prepare data
  // -------------------

  const testId = uuid();
  const coveredName = `AP covered - ${testId}`;
  const uncoveredName = `AP uncovered - ${testId}`;
  const coveredId = await addAttackPattern(request, coveredName);
  const uncoveredId = await addAttackPattern(request, uncoveredName);
  const reportResponse = await addReport(request, { name: `Report for SCR - ${testId}`, objects: [coveredId, uncoveredId] });
  const reportId = (await reportResponse.json()).data.reportAdd.id;
  const securityCoverageName = `Security Coverage - ${testId}`;
  const securityCoverageId = await addSecurityCoverage(request, { name: securityCoverageName, objectCovered: reportId });
  const resultName = `Manual result - ${testId}`;
  const resultId = await addSecurityCoverageResult(request, { name: resultName, resultOf: securityCoverageId, coveredIds: [coveredId] });

  // Has-covered relationships are created by a background task.
  const isCovering = (names: string[]) => async () => {
    const { coveredNames } = await getSecurityCoverageResult(request, resultId);
    return names.every((name) => coveredNames.includes(name));
  };
  await awaitUntilCondition(isCovering([coveredName]), 2000, 30);

  // ---------
  // endregion

  // region Update the manual result
  // -------------------------------

  await page.goto(`/dashboard/analyses/security_coverages/${securityCoverageId}`);
  await expect(securityCoverageDetails.getTitle(securityCoverageName)).toBeVisible();
  await securityCoverageDetails.tabs.goToResultTab();

  await resultForm.openUpdateForm();
  await expect(resultForm.getUpdateTitle()).toBeVisible();
  // Step 1: select the result to update
  await expect(resultForm.getResultFromList(resultName)).toBeVisible();
  await resultForm.selectResultToUpdate();
  // Step 2: details, prefilled with the values of the result
  await expect(resultForm.nameField.get()).toHaveValue(resultName);
  const updatedName = `Updated result - ${testId}`;
  await resultForm.nameField.fill(updatedName);
  await resultForm.goToNextStep();
  // Step 3: entities already covered by the result are hidden
  await expect(resultForm.getEntityFromList(uncoveredName)).toBeVisible();
  await expect(resultForm.getEntityFromList(coveredName)).toBeHidden();
  // No relationship to create until an entity is selected
  await expect(resultForm.getNextButton()).toBeDisabled();
  await resultForm.selectEntityFromList(uncoveredName);
  await expect(resultForm.getNextButton()).toBeEnabled();
  await resultForm.goToNextStep();
  // Step 4: has-covered relationships
  await resultForm.getCreateButton().click();
  await expect(resultForm.getUpdateTitle()).toBeHidden();

  // ---------
  // endregion

  // region Check the updated result
  // -------------------------------

  await awaitUntilCondition(isCovering([coveredName, uncoveredName]), 2000, 30);
  const updatedResult = await getSecurityCoverageResult(request, resultId);
  expect(updatedResult.name).toEqual(updatedName);
  expect(updatedResult.coveredNames.sort()).toEqual([coveredName, uncoveredName].sort());

  // ---------
  // endregion

  // region Delete data
  // ------------------

  await deleteSecurityCoverage(request, securityCoverageId);
  await deleteReport(request, reportId);
  await deleteAttackPattern(request, coveredId);
  await deleteAttackPattern(request, uncoveredId);

  // ---------
  // endregion
});
