import { Page } from '@playwright/test';

/**
 * The panel is rendered by the external `@filigran/chatbot` package, which
 * ships no `data-testid` and gives an accessible name to only some of its
 * controls. The unnamed header buttons are located by their lucide icon path:
 * an index would break the day a button is added, and the icons are what the
 * user actually recognises.
 */
const ICON_NEW_CHAT = 'M12 20h9';
const ICON_SWITCH_VIEW = 'M15 3v18';
const ICON_CLOSE = 'M18 6 6 18';

export default class AskArianePageModel {
  constructor(private page: Page) {}

  // The top bar button opens the panel. Its accessible name comes from the
  // tooltip, not from the visible 'Ask Ariane' label.
  getOpenButton() {
    return this.page.getByRole('button', { name: 'Open chatbot' });
  }

  getPanel() {
    return this.page.locator('#ask-ariane-portal .filigran-chatbot');
  }

  getPromptInput() {
    return this.getPanel().getByPlaceholder('Ask a question...');
  }

  getPromptSuggestion(suggestion: string) {
    return this.getPanel().getByRole('button', { name: suggestion });
  }

  getConversationHistoryButton() {
    return this.getPanel().getByRole('button', { name: 'Conversation history' });
  }

  getNewChatButton() {
    return this.getHeaderButton(ICON_NEW_CHAT);
  }

  getSwitchViewButton() {
    return this.getHeaderButton(ICON_SWITCH_VIEW);
  }

  getCloseButton() {
    return this.getHeaderButton(ICON_CLOSE);
  }

  private getHeaderButton(iconPath: string) {
    return this.getPanel().locator(`button:has(svg path[d="${iconPath}"])`);
  }

  // region Filigran AI terms
  // The chatbot stays behind a CGU gate until an administrator accepts the
  // terms, and a fresh platform starts with the status 'pending'. Clicking the
  // top bar button then opens the acceptance dialog instead of the panel.
  getTermsDialog() {
    return this.page.getByRole('dialog').filter({ hasText: 'Validate the Filigran AI Terms' });
  }

  getTermsAgreeButton() {
    return this.getTermsDialog().getByRole('button', { name: 'I Agree to Filigran AI Terms' });
  }

  /**
   * Opens the panel, accepting the Filigran AI terms first when the platform
   * has not accepted them yet, so the test does not depend on the CGU status it
   * starts from. Accepting is a platform-wide setting and is left enabled.
   */
  async open() {
    await this.getOpenButton().click();
    // Race the two possible outcomes of the click instead of probing for the
    // dialog, which is not rendered yet at that point.
    await this.getPanel().or(this.getTermsDialog()).waitFor();
    if (await this.getTermsDialog().isVisible()) {
      await this.getTermsDialog().getByRole('checkbox').check();
      await this.getTermsAgreeButton().click();
      await this.getTermsDialog().waitFor({ state: 'hidden' });
      await this.getOpenButton().click();
      await this.getPanel().waitFor();
    }
  }
  // endregion
}
