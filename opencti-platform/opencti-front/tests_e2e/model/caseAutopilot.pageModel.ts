import { Page } from '@playwright/test';

/** The Case Autopilot surfaces: the Ask AI menu entry, the Autopilot tab and the policies settings. */
export default class CaseAutopilotPage {
  constructor(private page: Page) {}

  getAskAIMenu() {
    return this.page.getByTestId('ask-ai-menu');
  }

  async openAskAIMenu() {
    await this.getAskAIMenu().click();
  }

  getRunCaseAutopilotItem() {
    return this.page.getByRole('menuitem', { name: /Run Case Autopilot/ });
  }

  getAutopilotTab() {
    return this.page.getByTestId('case-autopilot-tab');
  }

  getAutopilotEmptyState() {
    return this.page.getByTestId('case-autopilot-empty');
  }

  getLatestInvestigationLink() {
    return this.page.getByTestId('latest-investigation');
  }

  async gotoPolicies() {
    await this.page.goto('/dashboard/settings/customization/case_autopilot');
  }

  getPoliciesPage() {
    return this.page.getByTestId('investigation-policies-page');
  }

  getPolicyCards() {
    return this.page.getByTestId('investigation-policy-card');
  }

  getCreatePolicyButton() {
    return this.page.getByTestId('investigation-policy-create');
  }

  getSubmitPolicyButton() {
    return this.page.getByTestId('investigation-policy-submit');
  }
}
