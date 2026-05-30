import { createHash } from 'node:crypto';
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
import xtmOneClient from '../modules/xtm/one/xtm-one-client';
import { issueXtmJwt } from '../domain/xtm-auth';
import type { AuthContext } from '../types/user';
import { getHttpClient, getResponseError } from '../utils/http-client';
import { redisGetXtmAgentResponse, redisSetXtmAgentResponse } from '../database/redis';
import { checkDraftInContext } from './httpServer-draft';

const XTM_ONE_URL = nconf.get('xtm:xtm_one_url');
export const XTM_ONE_CHATBOT_URL = `${XTM_ONE_URL}/chatbot`;

// Default timeout for non-streaming XTM One HTTP calls (2 minutes).
// Streaming endpoints use timeout: 0 (no timeout) since the connection stays open.
const DEFAULT_XTM_TIMEOUT = 2 * 60 * 1000; // 2 minutes.

// Extended timeout for multipart file-based agent calls (10 minutes).
// File upload and analysis can take significantly longer than text-based calls.
const MULTIPART_XTM_TIMEOUT = 10 * 60 * 1000; // 10 minutes.

// TTL (in minutes) for caching XTM One agent responses in Redis. The cache
// is keyed by sha256(agent_slug + opencti-draft-id + content) so reopening
// AI Insights for the same entity within the window returns instantly, and
// live-workspace and draft views never share a cache entry. Set to 0 to
// disable. A non-numeric or negative override is treated as a misconfiguration
// and falls back to the default rather than silently disabling the cache.
// The seconds value is floored to an integer because Redis `SET ... EX` only
// accepts integer TTLs — a fractional minute override (e.g. `0.01`) would
// otherwise produce a `0.6s` TTL and fail with `ERR value is not an integer`,
// silently turning caching off.
const AI_AGENTS_REFRESH_TIMEOUT_DEFAULT_MINUTES = 1440;
const parsedAgentsRefreshTimeoutMinutes = Number(nconf.get('ai:agents_refresh_timeout'));
const AI_AGENTS_REFRESH_TIMEOUT_MINUTES = Number.isFinite(parsedAgentsRefreshTimeoutMinutes) && parsedAgentsRefreshTimeoutMinutes >= 0
  ? parsedAgentsRefreshTimeoutMinutes
  : AI_AGENTS_REFRESH_TIMEOUT_DEFAULT_MINUTES;
const AI_AGENTS_REFRESH_TIMEOUT_SECONDS = Math.floor(AI_AGENTS_REFRESH_TIMEOUT_MINUTES * 60);

// ── HTTP client (proxy-aware) ────────────────────────────────────────────
const getXtmClient = (responseType: 'json' | 'stream', headers?: Record<string, string>) => {
  return getHttpClient({
    baseURL: XTM_ONE_URL,
    responseType,
    headers,
  });
};

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
const generateBasicHeaders = async (req: Express.Request, context: AuthContext): Promise<Record<string, string>> => {
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
    const context = await createAuthenticatedContext(req, res, 'chatbot');
    if (!context.user) {
      res.sendStatus(403);
      return null;
    }
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
    const rawAgents = await xtmOneClient.listAgentsForIntent(context, intent);
    const agents = (rawAgents ?? [])
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
    const jwt = await issueXtmJwt(context.user, XTM_ONE_URL);
    const httpClient = getXtmClient('json', {
      Authorization: `Bearer ${jwt}`,
      'Content-Type': 'application/json',
    });
    const response = await httpClient.post('/api/v1/platform/chat/sessions', req.body, {
      timeout: DEFAULT_XTM_TIMEOUT,
    });
    res.json(response.data);
  } catch (e: unknown) {
    logApp.error('Error in chatbot session', { cause: e });
    const { message } = e as Error;
    const httpErr = getResponseError(e);
    if (httpErr) {
      setCookieError(res, message);
      res.status(httpErr.status).send({ status: httpErr.status, error: message });
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
    const httpClient = getXtmClient('stream', headers);
    const response = await httpClient.post('/api/v1/platform/chat/messages', req.body, {
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

    const httpErr = getResponseError(e);
    if (httpErr) {
      const code = httpErr.status;

      // For streaming responses, httpErr.data may be a stream, not parsed JSON.
      // Try to extract the detail from the response body.
      let detail = message;
      try {
        if (typeof httpErr.data === 'object' && httpErr.data !== null) {
          if ('detail' in httpErr.data) {
            detail = httpErr.data.detail;
          } else if (typeof httpErr.data.pipe === 'function') {
            // It's a stream — read the buffer
            const chunks: Buffer[] = [];
            for await (const chunk of httpErr.data) {
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
      const httpClient = getXtmClient('json', { ...authHeaders, ...form.getHeaders() });
      const uploadRes = await httpClient.post(
        `/api/v1/chat/conversations/${conversationId}/upload?create_message=false`,
        form,
        { timeout: MULTIPART_XTM_TIMEOUT, maxContentLength: Infinity, maxBodyLength: Infinity },
      );
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
    } else {
      const httpErr = getResponseError(e);
      if (httpErr) {
        const detail = httpErr.data?.detail ?? httpErr.data?.message ?? message;
        res.status(httpErr.status).json({ error: detail });
      } else {
        res.status(503).json({ error: 'XTM One is unreachable' });
      }
    }
  }
};

// ── GET /chatbot/files/:fileId/download ─────────────────────────────────
// Streams an agent-generated file from XTM One back to the browser.
//
// The OpenCTI user is authenticated here (platform session) and the XTM One
// JWT is minted server-side via `generateBasicHeaders` → `issueXtmJwt`. The
// user therefore never authenticates to XTM One directly: the embedded
// chatbot points its download URL at this proxy (relative to its
// `apiBaseUrl` of `${APP_BASE_PATH}/chatbot`), not at XTM One.
const FILE_ID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

export const getChatbotFileDownload = async (req: Express.Request, res: Express.Response) => {
  try {
    const context = await authenticateAndVerify(req, res);
    if (!context?.user) return;

    // `req.params` values are typed `string | string[]` in this codebase; a
    // single route segment is always a string at runtime, but coerce
    // defensively so a malformed value simply fails the UUID check below.
    const fileId = String(req.params.fileId ?? '');
    if (!fileId || !FILE_ID_RE.test(fileId)) {
      res.status(400).json({ error: 'Invalid file id' });
      return;
    }

    const headers = await generateBasicHeaders(req, context);
    const httpClient = getXtmClient('stream', headers);
    const response = await httpClient.get(`/api/v1/chat/files/${fileId}/download`, {
      decompress: false,
      // Streaming pipe — no response timeout (matches the other streaming
      // proxy calls). A 2-minute cap could abort a large/slow download
      // prematurely; the stream ends naturally and `req.on('close')` below
      // tears it down if the client disconnects.
      timeout: 0,
    });

    // Forward the content headers so the browser saves the file with the
    // right name and type. `content-disposition` is built CRLF-safe by XTM One.
    // `content-encoding` MUST be forwarded because `decompress: false` leaves a
    // gzip/br payload compressed — the browser needs the header to decode it.
    const forwardHeaders = ['content-type', 'content-disposition', 'content-length', 'content-encoding', 'cache-control'];
    Object.entries(response.headers).forEach(([key, value]) => {
      if (forwardHeaders.includes(key.toLowerCase()) && value) {
        res.setHeader(key, value as string);
      }
    });

    response.data.pipe(res);

    req.on('close', () => {
      response.data.destroy();
    });

    response.data.on('error', (error: Error) => {
      logApp.error('Stream error in chatbot file download proxy', { cause: error });
      if (!res.headersSent) {
        res.status(500).send({ status: 'error', error: error.message });
      } else {
        res.end();
      }
    });
  } catch (e: unknown) {
    logApp.error('Error in chatbot file download proxy', { cause: e });
    const { message } = e as Error;
    const httpErr = getResponseError(e);
    setCookieError(res, message);
    if (httpErr) {
      // Surface the upstream `detail` (e.g. "File not found" / "Access denied")
      // instead of the generic axios "Request failed with status code N".
      // With responseType 'stream' the error body may arrive as a stream, so
      // handle both the parsed-object and stream cases (matches the
      // `postChatbotMessage` error path).
      let detail = message;
      try {
        if (typeof httpErr.data === 'object' && httpErr.data !== null) {
          if ('detail' in httpErr.data) {
            detail = httpErr.data.detail;
          } else if (typeof httpErr.data.pipe === 'function') {
            const chunks: Buffer[] = [];
            for await (const chunk of httpErr.data) {
              chunks.push(Buffer.from(chunk));
            }
            const body = JSON.parse(Buffer.concat(chunks).toString('utf-8'));
            detail = body.detail ?? message;
          }
        }
      } catch {
        // If parsing fails, fall back to the generic error message.
      }
      res.status(httpErr.status).json({ error: detail });
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
      const jsonClient = getXtmClient('json', { ...authHeaders, 'Content-Type': 'application/json' });
      // 2. Create a session with the agent
      const sessionRes = await jsonClient.post('/api/v1/platform/chat/sessions', { agent_slug: agentSlug }, {
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
        const uploadClient = getXtmClient('json', { ...authHeaders, ...form.getHeaders() });
        const uploadRes = await uploadClient.post(
          `/api/v1/chat/conversations/${conversationId}/upload?create_message=false`,
          form,
          { timeout: MULTIPART_XTM_TIMEOUT, maxContentLength: Infinity, maxBodyLength: Infinity },
        );
        if (uploadRes.data?.file_id) {
          fileIds.push(uploadRes.data.file_id);
        }
      }
      if (fileIds.length === 0) {
        res.status(502).json({ error: 'Failed to upload files to XTM One' });
        return;
      }
      // 4. Send message with file_ids to trigger extraction
      const messageRes = await jsonClient.post(
        `/api/v1/chat/conversations/${conversationId}/messages`,
        { content: messageContent, file_ids: fileIds },
        { timeout: MULTIPART_XTM_TIMEOUT },
      );
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
      const httpClient = getXtmClient('json', headers);
      const response = await httpClient.post('/api/v1/platform/chat/messages', { agent_slug, content, stream: false }, {
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
    } else {
      const httpErr = getResponseError(e);
      if (httpErr) {
        logApp.error('XTM One error response', { status: httpErr.status, data: JSON.stringify(httpErr.data) });
        const detail = httpErr.data?.detail ?? httpErr.data?.message ?? message;
        setCookieError(res, message);
        res.status(200).json({ content: '', status: 'error', error: detail, code: httpErr.status });
      } else {
        const userMessage = 'XTM One is unreachable';
        setCookieError(res, userMessage);
        res.status(200).json({ content: '', status: 'error', error: userMessage, code: 503 });
      }
    }
  }
};

// ── Agent response cache helpers ────────────────────────────────────────

// Build a stable cache key from the agent slug, the draft context, and the
// user prompt. The draft id is part of the key because the same prompt run
// against the live workspace vs a draft would return different stats from
// the agent's OpenCTI-side callbacks, and replaying a live cache hit to a
// draft viewer (or vice-versa) would be incorrect.
const buildAgentCacheKey = (agentSlug: string, draftId: string, content: string): string => {
  return createHash('sha256').update(`${agentSlug}::${draftId}::${content}`).digest('hex');
};

// Set the SSE response headers once for both cache hits and live streams.
const writeAgentStreamHeaders = (res: Express.Response): void => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
};

// Parse a buffered SSE stream and return the content of the final `done` event,
// or null if the stream did not complete successfully (e.g. produced an error
// event, was aborted, or never emitted a `done`). Used to avoid caching
// partial / failed responses.
const extractFinalContent = (raw: string): string | null => {
  const lines = raw.split('\n');
  let lastDoneContent: string | null = null;
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('data: ')) continue;
    try {
      const event = JSON.parse(trimmed.slice(6));
      if (event.type === 'error') {
        return null;
      }
      if (event.type === 'done' && typeof event.content === 'string') {
        lastDoneContent = event.content;
      }
    } catch {
      // Skip malformed SSE lines
    }
  }
  return lastDoneContent;
};

// ── POST /chatbot/agent/stream ──────────────────────────────────────────
// Streaming agent call: sends a message with stream=true and pipes the
// SSE event stream back to the client for real-time rendering.
// Body: { agent_slug, content, force_refresh? }
// AskIA / Insight (no files), streamed to client
//
// Responses are cached in Redis keyed by
// sha256(agent_slug + opencti-draft-id + content) so that reopening AI
// Insights for the same entity within the TTL window
// (ai:agents_refresh_timeout, in minutes, default 1440) returns instantly
// instead of re-running an expensive agent execution. The draft id is
// part of the key so live-workspace and draft views never share a cache
// entry. Pass `force_refresh: true` to bypass the cache (e.g. when the
// user clicks the retry button).
export const postAgentMessageStream = async (req: Express.Request, res: Express.Response) => {
  try {
    const context = await authenticateAndVerify(req, res);
    if (!context?.user) return;
    const { agent_slug, content, force_refresh } = req.body || {};
    if (!agent_slug || !content) {
      res.status(400).json({ error: 'agent_slug and content are required' });
      return;
    }

    // REST routes don't go through the GraphQL `checkDraftInContext` middleware,
    // so validate the draft context explicitly before either serving a cached
    // response or hitting the upstream agent. Without this guard a caller could
    // pass an arbitrary `opencti-draft-id` header and get a cached response (or
    // a fresh agent run) for a draft they don't have access to, bypassing draft
    // authorization entirely. `checkDraftInContext` is a no-op when the
    // authenticated context has no draft, so the live-workspace path is
    // unaffected.
    try {
      await checkDraftInContext(context);
    } catch (draftErr: unknown) {
      logApp.warn('Agent stream rejected due to invalid draft context', { cause: draftErr });
      res.status(400).json({ error: (draftErr as Error)?.message || 'Invalid draft context' });
      return;
    }

    // Cache lookup — replay as a single `done` event so the client display
    // logic (which already handles `done`) doesn't need to know about cache.
    // The cache is intentionally not namespaced by user identity (matching
    // the pre-XTM-One in-memory `aiResponseCache` in `domain/container.js`),
    // but it MUST be namespaced by draft so live and draft views never
    // contaminate each other. We read the draft id from `context.draft_context`
    // (rather than the raw header) so that the value has gone through the same
    // shape validation the rest of the platform uses.
    const draftId = context.draft_context ?? '';
    const cacheEnabled = AI_AGENTS_REFRESH_TIMEOUT_SECONDS > 0;
    const cacheKey = cacheEnabled ? buildAgentCacheKey(agent_slug, draftId, content) : null;
    if (cacheEnabled && cacheKey && !force_refresh) {
      const cached = await redisGetXtmAgentResponse(cacheKey);
      if (cached) {
        logApp.info('Agent response served from cache', { agent_slug });
        writeAgentStreamHeaders(res);
        res.write(`data: ${JSON.stringify({
          type: 'done',
          content: cached.content,
          cached: true,
          generated_at: cached.cached_at,
        })}\n\n`);
        res.end();
        return;
      }
    }

    const headers = await generateBasicHeaders(req, context);
    // Force the upstream `opencti-draft-id` header to match the validated
    // `context.draft_context` used for the cache key. `generateBasicHeaders`
    // forwards the raw request header, but `context.draft_context` falls back
    // to `user.draft_context` when the request header is absent — without this
    // override, a user with an active session draft and no explicit header
    // would run the agent in the live workspace while the response gets
    // cached under the draft key (and vice-versa on the next cache hit).
    headers['opencti-draft-id'] = draftId;
    const httpClient = getXtmClient('stream', headers);
    const response = await httpClient.post('/api/v1/platform/chat/messages', {
      agent_slug,
      content,
      stream: true,
    }, {
      decompress: false,
      timeout: 0,
    });

    // Only set SSE response headers now that we know the upstream stream is
    // open. Setting them earlier would leak `Content-Type: text/event-stream`
    // into the catch branches below that respond with JSON.
    writeAgentStreamHeaders(res);

    // Capture the upstream bytes alongside the pipe so we can persist the
    // final content to Redis when the stream completes. A 2MB ceiling caps
    // memory usage for unusually large agent responses.
    let clientAborted = false;
    let streamErrored = false;
    let captureBytes = 0;
    let captureOverflow = false;
    const captureLimit = 2 * 1024 * 1024;
    const captureChunks: Buffer[] = [];
    response.data.on('data', (chunk: Buffer) => {
      if (captureOverflow) return;
      captureBytes += chunk.length;
      if (captureBytes > captureLimit) {
        captureOverflow = true;
        captureChunks.length = 0;
        return;
      }
      captureChunks.push(Buffer.from(chunk));
    });
    response.data.on('end', async () => {
      // Skip caching on transport errors (Node `'error'` event), client
      // aborts, capture overflow, or when the cache is disabled. Node
      // typically does not emit `'end'` after `'error'`, but the explicit
      // `streamErrored` guard is cheap insurance against caching a partial
      // or transport-failed response if a future Node / undici / axios
      // version reorders events.
      if (!cacheEnabled || !cacheKey || clientAborted || streamErrored || captureOverflow) return;
      const raw = Buffer.concat(captureChunks).toString('utf-8');
      const finalContent = extractFinalContent(raw);
      if (finalContent !== null && finalContent.length > 0) {
        await redisSetXtmAgentResponse(cacheKey, finalContent, AI_AGENTS_REFRESH_TIMEOUT_SECONDS);
      }
    });

    response.data.pipe(res);

    req.on('close', () => {
      clientAborted = true;
      response.data.destroy();
    });
    response.data.on('error', (error: Error) => {
      streamErrored = true;
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
    const httpErr = getResponseError(e);
    if (httpErr) {
      // For streaming responses, httpErr.data may be a stream, not parsed JSON.
      let detail = message;
      try {
        if (typeof httpErr.data === 'object' && httpErr.data !== null) {
          if ('detail' in httpErr.data) {
            detail = httpErr.data.detail;
          } else if (typeof httpErr.data.pipe === 'function') {
            const chunks: Buffer[] = [];
            for await (const chunk of httpErr.data) {
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

    const httpClient = getXtmClient('stream', headers);
    const response = await httpClient.post('/chatbot', enhancedBody, {
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

    const httpErr = getResponseError(e);
    if (httpErr) {
      res.status(httpErr.status).send({ status: httpErr.status, error: message });
    } else {
      res.status(503).send({ status: 503, error: message });
    }
    setCookieError(res, message);
  }
};
