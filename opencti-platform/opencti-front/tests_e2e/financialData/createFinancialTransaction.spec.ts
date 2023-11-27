import { expect, test } from "tests_e2e/fixtures/baseFixtures";
import ObservablePage from "tests_e2e/model/observable.pageModel";
import ObservableDetailsPage from "tests_e2e/model/observableDetails.pageModel";
import ObservableFormPage from "tests_e2e/model/observableForm.pageModel";

test('Create a new financial transaction', async ({ page }) => {
  const observablePage = new ObservablePage(page);
  const observableForm = new ObservableFormPage(page);
  const observableDetailsPage = new ObservableDetailsPage(page);
  const TRANSACTION_VALUE = '10000';
  const CURRENCY_CODE = 'united_states_dollar_(usd)';
  await page.goto('/dashboard/observations/financial-data');
  await observablePage.addNewObservable();
  await observablePage.addFinancialTransaction();
  await observableForm.fillTransactionValueInput(TRANSACTION_VALUE);
  await observableForm.fillCurrencyCode(CURRENCY_CODE);
  await observablePage.getCreateObservableButton().click();
  await observablePage.getItemFromList('Unknown').click();
  await expect(observableDetailsPage.getFinancialDataDetailsPage()).toBeVisible();
});