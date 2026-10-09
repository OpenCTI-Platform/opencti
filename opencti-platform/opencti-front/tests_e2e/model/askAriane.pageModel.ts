import { Page } from '@playwright/test';

/**
 * The panel is rendered by the external `@filigran/chatbot` package, which
 * ships no `data-testid` and gives an accessible name to only some of its
 * controls. The unnamed header buttons are located by their lucide icon path,
 * scoped to the tooltip wrappers the header uses: the same icons appear in the
 * mode menu and in the conversation list, so an unscoped path is ambiguous as
 * soon as one of those is open.
 */
const ICON_NEW_CHAT = 'M12 20h9';
const CGU_STATUS_FIELD = 'filigran_chatbot_ai_cgu_status';

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

  private getHeaderButton(iconPath: string) {
    return this.getPanel().locator(`span.inline-flex > button:has(svg path[d="${iconPath}"])`);
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
      // The dialog closes on click without waiting for its own mutation, so the
      // button would still read the old 'pending' status and just reopen it.
      const cguPatched = this.page.waitForResponse((response) => response.url().includes('/graphql')
        && (response.request().postData() ?? '').includes(CGU_STATUS_FIELD));
      await this.getTermsAgreeButton().click();
      await cguPatched;
      await this.getOpenButton().click();
      await this.getPanel().waitFor();
    }
  }
  // endregion
}
