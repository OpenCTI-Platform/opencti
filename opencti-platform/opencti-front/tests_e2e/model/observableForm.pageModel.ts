import { Page } from "@playwright/test";

export default class ObservableFormPage {
  constructor (private page: Page) {}

  getAccountNumberInput() {
    return this.page.getByRole('textbox', { name: 'account_number' });
  }

  getAccountTypeInput() {
    return this.page.getByRole('combobox', { name: 'account_type' });
  }

  getAssetValueInput() {
    return this.page.getByRole('spinbutton', { name: 'asset_value' });
  }

  getAssetType() {
    return this.page.getByRole('combobox', { name: 'asset_type' });
  }

  getTransactionValueInput() {
    return this.page.getByRole('spinbutton', { name: 'transaction_value' });
  }

  getCurrencyCode() {
    return this.page.getByRole('combobox', { name: 'currency_code' });
  }

  async fillAccountNumberInput(input: string) {
    await this.getAccountNumberInput().click();
    return this.getAccountNumberInput().fill(input);
  }

  async fillAccountTypeInput(input: string) {
    await this.getAccountTypeInput().click();
    return this.getAccountTypeInput().fill(input);
  }

  async fillAssetValueInput(input: string) {
    await this.getAssetValueInput().click();
    return this.getAssetValueInput().fill(input);
  }

  async fillAssetTypeInput(input: string) {
    await this.getAssetType().click();
    await this.getAssetType().fill(input);
    return this.getAssetType().press('Enter');
  }

  async fillTransactionValueInput(input: string) {
    await this.getTransactionValueInput().click();
    return this.getTransactionValueInput().fill(input);
  }

  async fillCurrencyCode(input: string) {
    await this.getCurrencyCode().click();
    return this.getCurrencyCode().fill(input);
  }
}
