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

  // The title is a Chip, not a control: it was a Button with
  // `pointer-events: none` and is now the library Chip, which renders a span.
  getPageTitle() {
    return this.page.getByText('GraphQL playground', { exact: true });
  }

  // Error boundary fallback shared by HighLevelError and SimpleError.
  getErrorMessage() {
    return this.page.getByText('An unknown error occurred');
  }
}
