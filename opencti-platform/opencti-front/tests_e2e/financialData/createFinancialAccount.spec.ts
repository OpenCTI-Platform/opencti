import { expect, test } from "tests_e2e/fixtures/baseFixtures";
import ObservablePage from "tests_e2e/model/observable.pageModel";
import ObservableDetailsPage from "tests_e2e/model/observableDetails.pageModel";
import ObservableFormPage from "tests_e2e/model/observableForm.pageModel";

test('Create a new financial account', async ({ page }) => {
  const observablePage = new ObservablePage(page);
  const observableForm = new ObservableFormPage(page);
  const observableDetailsPage = new ObservableDetailsPage(page);
  const ACCOUNT_NUMBER = '12345';
  const ACCOUNT_TYPE = 'depository_bank_account';
  await page.goto('/dashboard/observations/financial-data');
  await observablePage.addNewObservable();
  await observablePage.addFinancialAccount();
  await observableForm.fillAccountNumberInput(ACCOUNT_NUMBER);
  await observableForm.fillAccountTypeInput(ACCOUNT_TYPE);
  await observablePage.getCreateObservableButton().click();
  await observablePage.getItemFromList(ACCOUNT_NUMBER).click();
  await expect(observableDetailsPage.getFinancialDataDetailsPage()).toBeVisible();
  await expect(observableDetailsPage.getTitle()).toHaveText(ACCOUNT_NUMBER);
});