import { expect, test } from '../fixtures/baseFixtures';
import AskArianePageModel from '../model/askAriane.pageModel';
import { AGENT_DESCRIPTION, AGENT_NAME, PRESENTATION_EXCERPT, WIDGET_ERROR_MESSAGE, getUnstubbedChatbotRequests, mockChatbotBackend } from './chatbotBackendMock';

/**
 * Content of the test
 * -------------------
 * Open the Ask Ariane panel
 * Check the agent presentation and that no error is displayed
 * Ask a question and check the answer is streamed back
 * Start a new chat and check the conversation is reset
 */
test('Ask Ariane chatbot', { tag: ['@ee'] }, async ({ page }) => {
  const askAriane = new AskArianePageModel(page);

  await mockChatbotBackend(page);
  await page.goto('/dashboard');

  // region Open the chatbot
  // ----------------------
  await askAriane.open();
  await expect(askAriane.getPanel()).toBeVisible();
  await expect(askAriane.getPromptInput()).toBeVisible();
  // endregion

  // region The agent presents itself, without any error
  // --------------------------------------------------
  const panel = askAriane.getPanel();
  await expect(panel).toContainText(`How can ${AGENT_NAME} help you`);
  await expect(panel).toContainText(AGENT_DESCRIPTION);
  await expect(askAriane.getPromptSuggestion('What are the latest threats?')).toBeVisible();
  await expect(panel).not.toContainText(WIDGET_ERROR_MESSAGE);
  // endregion

  // region The agent answers a question
  // ----------------------------------
  await askAriane.getPromptInput().fill('Hello, who are you?');
  await askAriane.getPromptInput().press('Enter');
  await expect(panel).toContainText('Hello, who are you?');
  await expect(panel).toContainText(PRESENTATION_EXCERPT);
  await expect(panel).not.toContainText(WIDGET_ERROR_MESSAGE);
  // endregion

  // region Starting a new chat resets the conversation
  // -------------------------------------------------
  await askAriane.getNewChatButton().click();
  await expect(panel).not.toContainText('Hello, who are you?');
  await expect(panel).toContainText(`How can ${AGENT_NAME} help you`);
  await expect(panel).not.toContainText(WIDGET_ERROR_MESSAGE);
  // endregion

  // The scenario must hold without any XTM One reachable, so nothing the panel
  // asked for may have escaped the mock.
  expect(getUnstubbedChatbotRequests()).toEqual([]);
});
