import { expect, test } from "tests_e2e/fixtures/baseFixtures";
import ObservablePage from "tests_e2e/model/observable.pageModel";
import ObservableDetailsPage from "tests_e2e/model/observableDetails.pageModel";
import ObservableFormPage from "tests_e2e/model/observableForm.pageModel";

test('Create a new financial asset', async ({ page }) => {
  const observablePage = new ObservablePage(page);
  const observableForm = new ObservableFormPage(page);
  const observableDetailsPage = new ObservableDetailsPage(page);
  const ASSET_VALUE = '1000000';
  const ASSET_TYPE = 'airplane';
  const CURRENCY_CODE = 'united_states_dollar_(usd)';
  await page.goto('/dashboard/observations/financial-data');
  await observablePage.addNewObservable();
  await observablePage.addFinancialAsset();
  await observableForm.fillAssetValueInput(ASSET_VALUE);
  await observableForm.fillAssetTypeInput(ASSET_TYPE);
  await observableForm.fillCurrencyCode(CURRENCY_CODE);
  await observablePage.getCreateObservableButton().click();
  await observablePage.getItemFromList(ASSET_TYPE).click();
  await expect(observableDetailsPage.getFinancialDataDetailsPage()).toBeVisible();
  await expect(observableDetailsPage.getTitle()).toHaveText(ASSET_TYPE);
});