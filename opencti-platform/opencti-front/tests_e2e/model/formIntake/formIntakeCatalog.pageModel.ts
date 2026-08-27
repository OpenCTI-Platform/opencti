import { Page } from '@playwright/test';
import IntegrationsPage from '../integrations.pageModel';

/**
 * Wraps the Integrations > Available catalog page (`IntegrationsAvailable.tsx`), scoped to the
 * built-in "Form intake" card (`BuiltInIntegrationCard.tsx`, generic `data-testid="builtin-card"`
 * shared by every built-in kind - so it's filtered here by its visible label).
 */
export default class FormIntakeCatalogPageModel {
  constructor(private readonly page: Page) {
  }

  async goToDeployed() {
    const integrationsPage = new IntegrationsPage(this.page);
    await integrationsPage.navigateFromMenu();
    await integrationsPage.switchToTab('deployed');
    await integrationsPage.getDeployedPage().waitFor({ state: 'visible' });
  }

  async goToAvailable() {
    const integrationsPage = new IntegrationsPage(this.page);
    await integrationsPage.navigateFromMenu();
    await integrationsPage.switchToTab('available');
    await integrationsPage.getCatalogPage().waitFor({ state: 'visible' });
  }

  getFormIntakeCard() {
    return this.page.getByTestId('builtin-card').filter({ hasText: 'Form intake' });
  }

  /** Opens the "Create a form intake" drawer (requires the "Manage ingestion" capability). */
  clickCreateFormIntake() {
    return this.getFormIntakeCard().click();
  }
}
