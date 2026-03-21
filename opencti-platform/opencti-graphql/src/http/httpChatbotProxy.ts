import axios from 'axios';
import type Express from 'express';
import nconf from 'nconf';
import { createAuthenticatedContext } from './httpAuthenticatedContext';
import { getEntityFromCache } from '../database/cache';
import { CguStatus } from '../generated/graphql';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import { getEnterpriseEditionActivePem, getEnterpriseEditionInfo } from '../modules/settings/licensing';
import { getChatbotUrl, logApp, PLATFORM_VERSION } from '../config/conf';
import type { BasicStoreSettings } from '../types/settings';
import { setCookieError } from './httpUtils';
import { getDiscoveredIntentCatalog } from '../modules/xtm/one/xtm-one';
import { issueAuthenticationJWT } from '../domain/user';

const XTM_ONE_URL = nconf.get('xtm:xtm_one_url');
export const XTM_ONE_CHATBOT_URL = `${XTM_ONE_URL}/chatbot`;

// ── Helpers ─────────────────────────────────────────────────────────────

/**
 * Authenticate the request and verify chatbot prerequisites (CGU + license).
 * Returns the authenticated context or null (response already sent in that case).
 */
const authenticateAndVerify = async (req: Express.Request, res: Express.Response) => {
  const context = await createAuthenticatedContext(req, res, 'chatbot');
  if (!context.user) {
    res.sendStatus(403);
    return null;
  }

  const settings = await getEntityFromCache<BasicStoreSettings>(context, context.user, ENTITY_TYPE_SETTINGS);
  const isChatbotCGUAccepted: boolean = settings.filigran_chatbot_ai_cgu_status === CguStatus.Enabled;
  const { pem } = getEnterpriseEditionActivePem(settings);
  const licenseInfo = getEnterpriseEditionInfo(settings);
  const isLicenseValidated = pem !== undefined && licenseInfo.license_validated;

  if (!isChatbotCGUAccepted || !isLicenseValidated) {
    logApp.error('Chatbot not enabled', { cguStatus: settings.filigran_chatbot_ai_cgu_status, isLicenseValidated });
    res.status(400).json({ error: 'Chatbot is not enabled' });
    return null;
  }

  return context;
};

// ── GET /chatbot/config ──────────────────────────────────────────────────
// Returns chatbot configuration (XTM One URL) for the frontend.

export const getChatbotConfig = async (req: Express.Request, res: Express.Response) => {
  try {
    const context = await authenticateAndVerify(req, res);
    if (!context) return;

    res.json({ xtm_one_url: XTM_ONE_URL || null });
  } catch (e: unknown) {
    logApp.error('Error in chatbot config', { cause: e });
    res.status(503).send({ status: 'error', error: (e as Error).message });
  }
};

// ── GET /chatbot/agents ─────────────────────────────────────────────────
// Returns available agents from the stored intent catalog (no XTM One call).

export const getChatbotAgents = async (req: Express.Request, res: Express.Response) => {
  try {
    const context = await authenticateAndVerify(req, res);
    if (!context) return;

    const intent = (req.query.intent as string) || 'global.assistant';
    const catalog = getDiscoveredIntentCatalog();
    const intentEntry = catalog.find((entry) => entry.intent === intent);
    const agents = (intentEntry?.agents ?? [])
      .filter((a) => a.enabled)
      .map((a) => ({
        id: a.agent_id,
        name: a.agent_name,
        slug: a.agent_slug,
        description: a.agent_description,
      }));

    res.json(agents);
  } catch (e: unknown) {
    logApp.error('Error in chatbot agents', { cause: e });
    const { message } = e as Error;
    res.status(503).send({ status: 'error', error: message });
  }
};

// ── POST /chatbot/sessions ──────────────────────────────────────────────
// Proxies to XTM One Platform Chat API to create/resume a conversation.

export const postChatbotSession = async (req: Express.Request, res: Express.Response) => {
  try {
    const context = await authenticateAndVerify(req, res);
    if (!context) return;

    const url = `${XTM_ONE_URL}/api/v1/platform/chat/sessions`;
    const jwt = await issueAuthenticationJWT(context.user);
    const response = await axios.post(url, req.body, {
      headers: {
        Authorization: `Bearer ${jwt}`,
        'Content-Type': 'application/json',
      },
      timeout: 15000,
    });

    res.json(response.data);
  } catch (e: unknown) {
    logApp.error('Error in chatbot session', { cause: e });
    const { message } = e as Error;
    if (axios.isAxiosError(e) && e.response) {
      setCookieError(res, message);
      res.status(e.response.status).send({ status: e.response.status, error: message });
    } else {
      setCookieError(res, message);
      res.status(503).send({ status: 503, error: message });
    }
  }
};

// ── POST /chatbot/messages ──────────────────────────────────────────────
// Proxies to XTM One Platform Chat API (streaming SSE).

export const postChatbotMessage = async (req: Express.Request, res: Express.Response) => {
  try {
    const context = await authenticateAndVerify(req, res);
    if (!context) return;

    if (!req.body) {
      res.status(400).json({ error: 'Request body is missing' });
      return;
    }

    const url = `${XTM_ONE_URL}/api/v1/platform/chat/messages`;

    const jwt = await issueAuthenticationJWT(context.user);
    const response = await axios.post(url, req.body, {
      headers: {
        Authorization: `Bearer ${jwt}`,
        'Content-Type': 'application/json',
        'X-Platform-URL': getChatbotUrl(req),
        'X-Platform-Product': 'opencti',
        'X-Platform-Version': PLATFORM_VERSION,
      },
      responseType: 'stream',
      decompress: false,
      timeout: 0,
    });

    // Set SSE headers
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('X-Accel-Buffering', 'no');
    res.setHeader('Transfer-Encoding', 'chunked');

    // Pipe the response stream directly to client
    response.data.pipe(res);

    req.on('close', () => {
      response.data.destroy();
    });

    response.data.on('error', (error: Error) => {
      logApp.error('Stream error in chatbot proxy', { cause: error });
      if (!res.headersSent) {
        const { message } = error;
        res.status(500).send({ status: 'error', error: message });
      } else {
        res.end();
      }
    });
  } catch (e: unknown) {
    logApp.error('Error in chatbot proxy', { cause: e });
    const { message } = e as Error;

    if (axios.isAxiosError(e) && e.response) {
      const code = e.response.status;

      // For streaming responses, e.response.data may be a stream, not parsed JSON.
      // Try to extract the detail from the response body.
      let detail = message;
      try {
        if (typeof e.response.data === 'object' && e.response.data !== null) {
          if ('detail' in e.response.data) {
            detail = e.response.data.detail;
          } else if (typeof e.response.data.pipe === 'function') {
            // It's a stream — read the buffer
            const chunks: Buffer[] = [];
            for await (const chunk of e.response.data) {
              chunks.push(Buffer.from(chunk));
            }
            const body = JSON.parse(Buffer.concat(chunks).toString('utf-8'));
            detail = body.detail ?? message;
          }
        }
      } catch {
        // If parsing fails, fall back to the error message
      }

      // Return errors as SSE stream so the chatbot displays
      // the message instead of crashing with a generic error.
      setCookieError(res, message);
      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache, no-transform');
      res.setHeader('Connection', 'keep-alive');
      res.status(200);

      const errorContent = code === 429
        ? `⚠️ **Quota exceeded** — ${detail}`
        : `⚠️ **Error** — ${detail}`;

      res.write(`data: ${JSON.stringify({ type: 'error', content: errorContent, code })}\n\n`);
      res.end();
    } else {
      setCookieError(res, message);
      res.status(503).send({ status: 503, error: message });
    }
  }
};

// ── POST /chatbot/agent ─────────────────────────────────────────────────
// Non-streaming agent call: sends a message, waits for the full response,
// and returns only the content string.
// Body: { agent_slug, content }

export const postAgentMessage = async (req: Express.Request, res: Express.Response) => {
  try {
    const context = await authenticateAndVerify(req, res);
    if (!context) return;

    const { agent_slug, content } = req.body || {};
    if (!agent_slug || !content) {
      res.status(400).json({ error: 'agent_slug and content are required' });
      return;
    }

    const url = `${XTM_ONE_URL}/api/v1/platform/chat/messages`;
    const jwt = await issueAuthenticationJWT(context.user);
    const response = await axios.post(url, {
      agent_slug,
      content,
      stream: false,
    }, {
      headers: {
        Authorization: `Bearer ${jwt}`,
        'Content-Type': 'application/json',
        'X-Platform-URL': getChatbotUrl(req),
        'X-Platform-Product': 'opencti',
        'X-Platform-Version': PLATFORM_VERSION,
      },
      timeout: 120000, // 2 min for non-streaming agent response
    });

    // XTM One returns { message_id, content } for non-streaming requests
    res.json({ content: response.data?.content ?? '', status: 'success' });
  } catch (e: unknown) {
    logApp.error('Error in agent message proxy', { cause: e });
    const { message } = e as Error;
    if (axios.isAxiosError(e) && e.response) {
      const detail = e.response.data?.detail ?? message;
      setCookieError(res, message);
      res.status(200).json({ content: '', status: 'error', error: detail, code: e.response.status });
    } else {
      setCookieError(res, message);
      res.status(200).json({ content: '', status: 'error', error: message, code: 503 });
    }
  }
};
