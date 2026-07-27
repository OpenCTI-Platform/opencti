import { Page } from '@playwright/test';

export default class PlaygroundPage {
  constructor(private page: Page) {}

  async goto() {
    await this.page.goto('/public/graphql');
  }

  // The GraphiQL editor container, rendered once the playground is loaded.
  getPage() {
    return this.page.locator('.graphiql-container');
  }

  getPageTitle() {
    return this.page.getByRole('button', { name: 'GraphQL playground' });
  }

  // Error boundary fallback shared by HighLevelError and SimpleError.
  getErrorMessage() {
    return this.page.getByText('An unknown error occurred');
  }
}
