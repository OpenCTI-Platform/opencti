import { Page } from '@playwright/test';

export default class WidgetFormPage {
  constructor(private page: Page) {
  }

  getTextWidgetButton() {
    return this.page.getByTestId('FormatShapesOutlinedIcon');
  }

  getTextWidgetTitleInput() {
    return this.page.getByLabel('Title');
  }

  async fillTextWidgetTitleInput(input: string) {
    await this.getTextWidgetTitleInput().click();
    return this.getTextWidgetTitleInput().fill(input);
  }

  getTextWidgetContentInput() {
    return this.page.getByTestId('text-area');
  }

  async fillTextWidgetContentInput(input: string) {
    await this.getTextWidgetContentInput().click();
    return this.getTextWidgetContentInput().fill(input);
  }

  getWidgetSubmitButton() {
    return this.page.getByTestId('widget-submit-button');
  }
}
