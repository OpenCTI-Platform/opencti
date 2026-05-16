import axios from 'axios';
import type Express from 'express';
import nconf from 'nconf';
import Busboy from 'busboy';
import FormData from 'form-data';
import { createAuthenticatedContext } from './httpAuthenticatedContext';
import { getEntityFromCache } from '../database/cache';
import { CguStatus } from '../generated/graphql';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import { getEnterpriseEditionActivePem, getEnterpriseEditionInfo } from '../modules/settings/licensing';
import { getChatbotUrl, logApp, PLATFORM_VERSION } from '../config/conf';
import type { BasicStoreSettings } from '../types/settings';
import { setCookieError } from './httpUtils';
import { getDiscoveredIntentCatalog } from '../modules/xtm/one/xtm-one';
import xtmOneClient from '../modules/xtm/one/xtm-one-client';
import { issueXtmJwt } from '../domain/xtm-auth';
import type { AuthContext } from '../types/user';

const XTM_ONE_URL = nconf.get('xtm:xtm_one_url');
export const XTM_ONE_CHATBOT_URL = `${XTM_ONE_URL}/chatbot`;

// Default timeout for non-streaming XTM One HTTP calls (2 minutes).
// Streaming endpoints use timeout: 0 (no timeout) since the connection stays open.
const DEFAULT_XTM_TIMEOUT = 2 * 60 * 1000; // 2 minutes.

// Extended timeout for multipart file-based agent calls (10 minutes).
// File upload and analysis can take significantly longer than text-based calls.
const MULTIPART_XTM_TIMEOUT = 10 * 60 * 1000; // 10 minutes.

// ── Multipart parsing helper ────────────────────────────────────────────

interface ParsedMultipart {
  files: { fieldname: string; filename: string; encoding: string; mimetype: string; data: Buffer }[];
  fields: Record<string, string>;
}

const parseMultipart = (req: Express.Request): Promise<ParsedMultipart> => {
  return new Promise((resolve, reject) => {
    const busboy = Busboy({ headers: req.headers, limits: { fileSize: 50 * 1024 * 1024 } }); // 50MB limit
    const files: ParsedMultipart['files'] = [];
    const fields: Record<string, string> = {};
    let truncated = false;
    busboy.on('file', (fieldname: string, stream: NodeJS.ReadableStream & { truncated?: boolean }, info: { filename: string; encoding: string; mimeType: string }) => {
      const chunks: Buffer[] = [];
      stream.on('data', (chunk: Buffer) => chunks.push(chunk));
      stream.on('limit', () => truncated = true);
      stream.on('end', () => {
        files.push({ fieldname, filename: info.filename, encoding: info.encoding, mimetype: info.mimeType, data: Buffer.concat(chunks) });
      });
    });
    busboy.on('field', (name: string, value: string) => fields[name] = value);
    busboy.on('finish', () => {
      if (truncated) {
        reject(new Error('File exceeds maximum size limit'));
      } else {
        resolve({ files, fields });
      }
    });
    busboy.on('error', (err: Error) => reject(err));
    req.pipe(busboy);
  });
};

// ── Helpers ─────────────────────────────────────────────────────────────
const generateBasicHeaders = async (req: Express.Request, context: AuthContext) => {
  if (!context?.user) return {};
  const jwt = await issueXtmJwt(context.user, XTM_ONE_URL);
  return {
    Authorization: `Bearer ${jwt}`,
    'Content-Type': 'application/json',
    'X-Platform-URL': getChatbotUrl(req),
    'X-Platform-Product': 'opencti',
    'X-Platform-Version': PLATFORM_VERSION,
    'opencti-draft-id': req.headers['opencti-draft-id'] as string || '',
  };
};

/**
 * Authenticate the request and verify chatbot prerequisites (CGU + license).
 * Returns the authenticated context or null (response already sent in that case).
 *
 * When XTM One is configured, the license check is relaxed because XTM One
 * handles its own licensing validation during registration.
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
    logApp.info('Chatbot not enabled', { cguStatus: settings.filigran_chatbot_ai_cgu_status, isLicenseValidated });
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

    res.json({
      xtm_one_url: XTM_ONE_URL || null,
      xtm_one_configured: xtmOneClient.isConfigured(),
    });
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
    const catalog = await getDiscoveredIntentCatalog();
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
    if (!context?.user) return;
    const url = `${XTM_ONE_URL}/api/v1/platform/chat/sessions`;
    const jwt = await issueXtmJwt(context.user, XTM_ONE_URL);
    const response = await axios.post(url, req.body, {
      headers: {
        Authorization: `Bearer ${jwt}`,
        'Content-Type': 'application/json',
      },
      timeout: DEFAULT_XTM_TIMEOUT,
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
// When file_ids are present in the body, routes to the conversation-level
// messages endpoint so that uploaded files are visible to the agent.
// Chat stream (conversationId available or not)
export const postChatbotMessage = async (req: Express.Request, res: Express.Response) => {
  try {
    const context = await authenticateAndVerify(req, res);
    if (!context?.user) return;

    if (!req.body) {
      res.status(400).json({ error: 'Request body is missing' });
      return;
    }

    const headers = await generateBasicHeaders(req, context);
    const url = `${XTM_ONE_URL}/api/v1/platform/chat/messages`;
    const response = await axios.post(url, req.body, {
      headers,
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

// ── POST /chatbot/upload ─────────────────────────────────────────────────
// Uploads files to an existing XTM One conversation and returns file_ids.
// The chatbot UI calls this before sending a message with file_ids.
// Accepts multipart/form-data with:
//   - conversation_id field (required)
//   - one or more file fields
// Returns: { file_ids: string[] }
// Upload files in conversation
export const postChatbotUpload = async (req: Express.Request, res: Express.Response) => {
  try {
    const context = await authenticateAndVerify(req, res);
    if (!context?.user) return;
    const { files, fields } = await parseMultipart(req);
    const conversationId = fields.conversation_id;
    if (!conversationId || files.length === 0) {
      res.status(400).json({ error: 'conversation_id field and at least one file are required' });
      return;
    }
    const authHeaders = await generateBasicHeaders(req, context);
    const fileIds: string[] = [];
    for (const file of files) {
      const form = new FormData();
      form.append('file', file.data, { filename: file.filename, contentType: file.mimetype });
      const uploadUri = `${XTM_ONE_URL}/api/v1/chat/conversations/${conversationId}/upload?create_message=false`;
      const uploadRes = await axios.post(uploadUri, form, {
        headers: { ...authHeaders, ...form.getHeaders() },
        timeout: MULTIPART_XTM_TIMEOUT,
        maxContentLength: Infinity,
        maxBodyLength: Infinity,
      });
      if (uploadRes.data?.file_id) {
        fileIds.push(uploadRes.data.file_id);
      }
    }
    if (fileIds.length === 0) {
      res.status(502).json({ error: 'Failed to upload files to XTM One' });
      return;
    }
    res.json({ file_ids: fileIds });
  } catch (e: unknown) {
    logApp.error('Error in chatbot upload', { cause: e });
    const { message } = e as Error;
    if (message?.includes('maximum size limit')) {
      res.status(413).json({ error: message });
    } else if (axios.isAxiosError(e) && e.response) {
      const detail = e.response.data?.detail ?? e.response.data?.message ?? message;
      res.status(e.response.status).json({ error: detail });
    } else {
      res.status(503).json({ error: 'XTM One is unreachable' });
    }
  }
};

// ── POST /chatbot/agent ─────────────────────────────────────────────────
// Non-streaming agent call.
// Accepts two Content-Type modes:
//   1. application/json — text-based: { agent_slug, content }
//   2. multipart/form-data — file-based: files[] + agent_slug field
// In multipart mode, files are proxied to XTM One and a STIX bundle is returned.
// Require direct response (files support through multipart), not streamable
export const postAgentMessage = async (req: Express.Request, res: Express.Response) => {
  try {
    const context = await authenticateAndVerify(req, res);
    if (!context?.user) return;

    const isMultipart = (req.headers['content-type'] ?? '').includes('multipart/form-data');
    const messageUri = `${XTM_ONE_URL}/api/v1/platform/chat/messages`;

    if (isMultipart) {
      // File-based mode: 3-step flow via XTM One chat API
      // 1. Parse incoming multipart
      const { files, fields } = await parseMultipart(req);
      const agentSlug = fields.agent_slug;
      const messageContent = fields.content;
      if (!agentSlug || !messageContent || files.length === 0) {
        res.status(400).json({ error: 'agent_slug, content fields and at least one file are required' });
        return;
      }
      const authHeaders = await generateBasicHeaders(req, context);
      // 2. Create a session with the agent
      const sessionUri = `${XTM_ONE_URL}/api/v1/platform/chat/sessions`;
      const sessionRes = await axios.post(sessionUri, { agent_slug: agentSlug }, {
        headers: { ...authHeaders, 'Content-Type': 'application/json' },
        timeout: DEFAULT_XTM_TIMEOUT,
      });
      const conversationId = sessionRes.data?.conversation_id;
      if (!conversationId) {
        res.status(502).json({ error: 'Failed to create XTM One session' });
        return;
      }
      // 3. Upload each file to the conversation (create_message=false to get file_ids)
      const fileIds: string[] = [];
      for (const file of files) {
        const form = new FormData();
        form.append('file', file.data, { filename: file.filename, contentType: file.mimetype });
        const uploadUri = `${XTM_ONE_URL}/api/v1/chat/conversations/${conversationId}/upload?create_message=false`;
        const uploadRes = await axios.post(uploadUri, form, {
          headers: { ...authHeaders, ...form.getHeaders() },
          timeout: MULTIPART_XTM_TIMEOUT,
          maxContentLength: Infinity,
          maxBodyLength: Infinity,
        });
        if (uploadRes.data?.file_id) {
          fileIds.push(uploadRes.data.file_id);
        }
      }
      if (fileIds.length === 0) {
        res.status(502).json({ error: 'Failed to upload files to XTM One' });
        return;
      }
      // 4. Send message with file_ids to trigger extraction
      const conversationUri = `${XTM_ONE_URL}/api/v1/chat/conversations/${conversationId}/messages`;
      const messageRes = await axios.post(conversationUri, { content: messageContent, file_ids: fileIds }, {
        headers: { ...authHeaders, 'Content-Type': 'application/json' },
        timeout: MULTIPART_XTM_TIMEOUT,
      });
      // Return the response from XTM One
      res.json(messageRes.data);
    } else {
      // Text-based mode
      const { agent_slug, content } = req.body || {};
      if (!agent_slug || !content) {
        res.status(400).json({ error: 'agent_slug and content are required' });
        return;
      }
      const headers = await generateBasicHeaders(req, context);
      const response = await axios.post(messageUri, { agent_slug, content, stream: false }, {
        headers,
        timeout: DEFAULT_XTM_TIMEOUT,
      });
      // XTM One returns { message_id, content } for non-streaming requests
      res.json({ content: response.data?.content ?? '', status: 'success' });
    }
  } catch (e: unknown) {
    logApp.error('Error in agent message proxy', { cause: e });
    const { message } = e as Error;
    if (message?.includes('maximum size limit')) {
      res.status(413).json({ error: message });
    } else if (axios.isAxiosError(e) && e.response) {
      const responseData = e.response.data;
      logApp.error('XTM One error response', { status: e.response.status, data: JSON.stringify(responseData) });
      const detail = responseData?.detail ?? responseData?.message ?? message;
      setCookieError(res, message);
      res.status(200).json({ content: '', status: 'error', error: detail, code: e.response.status });
    } else {
      const userMessage = 'XTM One is unreachable';
      setCookieError(res, userMessage);
      res.status(200).json({ content: '', status: 'error', error: userMessage, code: 503 });
    }
  }
};

// ── POST /chatbot/agent/stream ──────────────────────────────────────────
// Streaming agent call: sends a message with stream=true and pipes the
// SSE event stream back to the client for real-time rendering.
// Body: { agent_slug, content }
// AskIA / Insight (no files), streamed to client
export const postAgentMessageStream = async (req: Express.Request, res: Express.Response) => {
  try {
    const context = await authenticateAndVerify(req, res);
    if (!context?.user) return;
    const { agent_slug, content } = req.body || {};
    if (!agent_slug || !content) {
      res.status(400).json({ error: 'agent_slug and content are required' });
      return;
    }
    const url = `${XTM_ONE_URL}/api/v1/platform/chat/messages`;
    const headers = await generateBasicHeaders(req, context);
    const response = await axios.post(url, {
      agent_slug,
      content,
      stream: true,
    }, {
      headers,
      responseType: 'stream',
      decompress: false,
      timeout: 0,
    });
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    response.data.pipe(res);
    req.on('close', () => {
      response.data.destroy();
    });
    response.data.on('error', (error: Error) => {
      logApp.error('Stream error in agent stream proxy', { cause: error });
      if (!res.headersSent) {
        res.status(500).send({ status: 'error', error: error.message });
      } else {
        res.end();
      }
    });
  } catch (e: unknown) {
    logApp.error('Error in agent stream proxy', { cause: e });
    const { message } = e as Error;
    if (axios.isAxiosError(e) && e.response) {
      // For streaming responses, e.response.data may be a stream, not parsed JSON.
      let detail = message;
      try {
        if (typeof e.response.data === 'object' && e.response.data !== null) {
          if ('detail' in e.response.data) {
            detail = e.response.data.detail;
          } else if (typeof e.response.data.pipe === 'function') {
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
      setCookieError(res, message);
      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache, no-transform');
      res.status(200);
      res.write(`data: ${JSON.stringify({ type: 'error', content: `⚠️ **Error** — ${detail}` })}\n\n`);
      res.end();
    } else {
      const userMessage = 'XTM One is unreachable';
      setCookieError(res, userMessage);
      res.status(503).send({ status: 503, error: userMessage });
    }
  }
};

// ── POST /chatbot (legacy Flowise proxy) ────────────────────────────────
// Used when XTM One is NOT configured (no xtm_one_token).
// Proxies to the Flowise-based chatbot at ${XTM_ONE_URL}/chatbot with
// PEM-based authentication.
export const getLegacyChatbotProxy = async (req: Express.Request, res: Express.Response) => {
  try {
    const context = await createAuthenticatedContext(req, res, 'chatbot');
    if (!context.user) {
      res.sendStatus(403);
      return;
    }

    const settings = await getEntityFromCache<BasicStoreSettings>(context, context.user, ENTITY_TYPE_SETTINGS);
    const isChatbotCGUAccepted: boolean = settings.filigran_chatbot_ai_cgu_status === CguStatus.Enabled;
    const { pem } = getEnterpriseEditionActivePem(settings);
    const licenseInfo = getEnterpriseEditionInfo(settings);
    const isLicenseValidated = pem !== undefined && licenseInfo.license_validated;

    if (!isChatbotCGUAccepted || !isLicenseValidated) {
      logApp.error('Error in legacy chatbot proxy', {
        cguStatus: settings.filigran_chatbot_ai_cgu_status,
        isLicenseValidated,
        chatbotUrl: XTM_ONE_CHATBOT_URL,
      });
      res.status(400).json({ error: 'Chatbot is not enabled' });
      return;
    }

    const jwt = await issueXtmJwt(context.user, XTM_ONE_URL);
    const vars = {
      OPENCTI_URL: getChatbotUrl(req),
      OPENCTI_TOKEN: jwt,
      'X-API-KEY': Buffer.from(pem as string, 'utf-8').toString('base64'),
      X_XTM_PRODUCT: 'OpenCTI',
      X_OPENCTI_VERSION: PLATFORM_VERSION,
    };

    const headers = {
      'Content-Type': 'application/json',
      Accept: 'text/event-stream',
      ...vars,
    };
    if (!req.body) {
      res.status(400).json({ error: 'Chatbot request body is missing' });
      return;
    }
    const enhancedBody = {
      ...req.body,
      overrideConfig: {
        ...req.body?.overrideConfig,
        vars: {
          ...req.body?.overrideConfig?.vars,
          ...vars,
        },
      },
    };

    const response = await axios.post(XTM_ONE_CHATBOT_URL, enhancedBody, {
      headers,
      responseType: 'stream',
      decompress: false,
      timeout: 0,
    });

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('X-Accel-Buffering', 'no');
    res.setHeader('Transfer-Encoding', 'chunked');
    const headersToForward = ['content-type', 'cache-control', 'connection'];
    Object.entries(response.headers).forEach(([key, value]) => {
      const lowerKey = key.toLowerCase();
      if (headersToForward.includes(lowerKey) && value) {
        res.setHeader(key, value);
      }
    });

    response.data.pipe(res);

    req.on('close', () => {
      response.data.destroy();
    });

    response.data.on('error', (error: Error) => {
      logApp.error('Stream error in legacy chatbot proxy', { cause: error });
      if (!res.headersSent) {
        res.status(500).send({ status: 'error', error: error.message });
      } else {
        res.end();
      }
    });
  } catch (e: unknown) {
    logApp.error('Error in legacy chatbot proxy', { cause: e });
    const { message } = e as Error;

    if (axios.isAxiosError(e) && e.response) {
      res.status(e.response.status).send({ status: e.response.status, error: message });
    } else {
      res.status(503).send({ status: 503, error: message });
    }
    setCookieError(res, message);
  }
};
