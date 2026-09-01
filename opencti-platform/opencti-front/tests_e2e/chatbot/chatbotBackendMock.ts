import { Page } from '@playwright/test';

/**
 * The Ask Ariane panel talks to the `/chatbot/*` proxy, which needs an XTM One
 * instance the CI environment does not have (no `xtm_one_token`, so
 * `/chatbot/config` reports `xtm_one_configured: false` and the panel never
 * mounts). The whole REST layer is therefore stubbed with payloads recorded
 * from a real XTM One session, which keeps the scenario deterministic — a live
 * agent would paraphrase its own presentation on every run.
 */

export const AGENT_NAME = 'CTEM Assistant';
export const AGENT_DESCRIPTION = 'Primary entry point of the XTM One platform.';
export const AGENT_SLUG = 'ctem-assistant';

// A sentence the presentation answer must contain, short enough to survive
// markdown rendering (the widget strips the `**` emphasis).
export const PRESENTATION_EXCERPT = 'What would you like help with today?';

// Asked by the test, and the title the history menu shows for that conversation.
export const QUESTION = 'Hello, who are you?';

/**
 * Every error the widget can render on its own: a failed turn, a request that
 * never reached the proxy, and a stream that ended without a `done` event.
 * Anything else it displays comes from the proxy and replaces the assistant
 * message content.
 */
export const WIDGET_ERROR_MESSAGES = /Sorry, an error occurred|Unable to connect|No response\./;

const CONVERSATION_ID = '89d60741-81c1-45c8-8d73-ce0ded38bf6f';
const MESSAGE_ID = '786d810d-34f8-48f6-ad61-f8f18707b79a';

const AGENTS = [
  {
    id: '73b39208-e45e-4660-bd43-ff057a12d5dd',
    name: AGENT_NAME,
    slug: AGENT_SLUG,
    description: AGENT_DESCRIPTION,
  },
  {
    id: '54f6d934-3bf1-434e-919c-3605f76c8482',
    name: 'OpenCTI Assistant',
    slug: 'opencti-assistant',
    description: 'Cyber Threat Intelligence analyst for OpenCTI.',
  },
];

const PRESENTATION_ANSWER = [
  `I'm the **${AGENT_NAME}** — your entry point on the XTM One platform.`,
  '',
  '## What I do',
  '- Act as the **central coordinator** across the platform specialists',
  '- Have **direct access to OpenCTI** so I can look up threats and campaigns myself',
  '',
  PRESENTATION_EXCERPT,
].join('\n');

// Server-sent events, in the order and shape XTM One streams them.
const MESSAGES_STREAM = [
  { type: 'status', status: 'preparing', phase: 'memory' },
  { type: 'status', status: 'preparing', phase: 'integrations' },
  { type: 'status', status: 'thinking', iteration: 1 },
  { type: 'status', status: 'streaming' },
  { type: 'stream', content: PRESENTATION_ANSWER },
  {
    type: 'done',
    content: PRESENTATION_ANSWER,
    conversation_id: CONVERSATION_ID,
    message_id: MESSAGE_ID,
  },
].map((event) => `data: ${JSON.stringify(event)}\n\n`).join('');

// POST resumes a conversation and replays its messages.
const SESSION = {
  conversation_id: CONVERSATION_ID,
  messages: [
    { role: 'user', content: QUESTION },
    { role: 'assistant', content: PRESENTATION_ANSWER },
  ],
};

// GET lists the conversations, and is requested when the history menu opens.
const SESSIONS = {
  conversations: [
    {
      conversation_id: CONVERSATION_ID,
      title: QUESTION,
      updated_at: '2026-09-01T09:08:20.357532+00:00',
      message_count: 2,
      agent_id: AGENTS[0].id,
      agent_name: AGENT_NAME,
    },
  ],
};

const json = (body: unknown) => ({
  status: 200,
  contentType: 'application/json',
  body: JSON.stringify(body),
});

const unstubbedRequests: string[] = [];

/**
 * Paths the widget asks for that the OpenCTI proxy does not serve: `/chat/*`
 * falls through to the SPA catch-all (`app.get('*any')` in `httpPlatform.js`),
 * which answers 200 with the index page. Serving HTML rather than a 404 keeps
 * the widget on the same branch as in production, where `r.ok` holds and the
 * JSON parse is what fails.
 */
const UNSERVED_BY_PROXY = '**/chatbot/chat/**';
const SPA_INDEX = '<!doctype html><html lang="en"><head><title>OpenCTI</title></head><body><div id="root"></div></body></html>';

/**
 * Everything the panel requested during the test that the mock did not expect.
 * Asserting this stays empty keeps the scenario honest: the day a widget
 * version calls a new endpoint, the test says so instead of silently relying on
 * a real XTM One being reachable.
 */
export const getUnstubbedChatbotRequests = () => [...unstubbedRequests];

/**
 * Playwright consults route handlers in reverse registration order, so the
 * catch-all goes in first and the specific routes below override it.
 */
export const mockChatbotBackend = async (page: Page) => {
  unstubbedRequests.length = 0;

  await page.route('**/chatbot/**', (route) => {
    unstubbedRequests.push(new URL(route.request().url()).pathname);
    return route.fulfill({ status: 404, contentType: 'application/json', body: '{}' });
  });

  await page.route(UNSERVED_BY_PROXY, (route) => route.fulfill({
    status: 200,
    contentType: 'text/html',
    body: SPA_INDEX,
  }));

  await page.route('**/chatbot/config', (route) => route.fulfill(json({
    xtm_one_url: 'http://localhost:8100',
    xtm_one_configured: true,
  })));

  await page.route('**/chatbot/agents**', (route) => route.fulfill(json(AGENTS)));

  await page.route('**/chatbot/sessions', (route) => route.fulfill(
    json(route.request().method() === 'GET' ? SESSIONS : SESSION),
  ));

  await page.route('**/chatbot/messages', (route) => route.fulfill({
    status: 200,
    contentType: 'text/event-stream',
    body: MESSAGES_STREAM,
  }));
};
