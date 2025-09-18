import axios from 'axios';
import type Express from 'express';
import { createAuthenticatedContext } from './httpAuthenticatedContext';
import { getEntityFromCache } from '../database/cache';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import { getEnterpriseEditionActivePem } from '../modules/settings/licensing';
import { getChatbotUrl, logApp, PLATFORM_VERSION } from '../config/conf';
import type { BasicStoreSettings } from '../types/settings';
import { setCookieError } from './httpUtils';
import { getFiligranChatbotAiEndpoint, isFiligranChatbotAiActivated } from '../modules/ai/chatbot-ai-settings';

export const getChatbotProxy = async (req: Express.Request, res: Express.Response) => {
  try {
    const context = await createAuthenticatedContext(req, res, 'chatbot');
    if (!context.user) {
      res.sendStatus(403);
      return;
    }

    const chatbotUrl = getFiligranChatbotAiEndpoint();
    const settings = await getEntityFromCache<BasicStoreSettings>(context, context.user, ENTITY_TYPE_SETTINGS);
    const license_pem = getEnterpriseEditionActivePem(settings.enterprise_license);
    const isChatbotAiActivated = await isFiligranChatbotAiActivated(settings);
    if (!isChatbotAiActivated || !license_pem) {
      res.status(400).json({ error: 'Chatbot is not enabled' });
      return;
    }
    if (!chatbotUrl) {
      res.status(400).json({ error: 'Chatbot proxy not properly configured' });
      return;
    }

    const vars = {
      OPENCTI_URL: getChatbotUrl(req),
      OPENCTI_TOKEN: context.user?.api_token,
      'X-API-KEY': Buffer.from(license_pem, 'utf-8').toString('base64'),
      X_XTM_PRODUCT: 'OpenCTI',
      X_OPENCTI_VERSION: PLATFORM_VERSION,
    };

    // Enhance headers with url, token and certificate
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
        }
      }
    };

    // Repost the request to Flowise with enhanced headers and body
    const response = await axios.post(chatbotUrl, enhancedBody, {
      headers,
      responseType: 'stream',
      decompress: false,
      timeout: 0,
    });

    // Set SSE headers and forward Flowise headers
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

    // Pipe the response stream directly to client
    response.data.pipe(res);

    req.on('close', () => {
      response.data.destroy();
    });

    response.data.on('error', (error: Error) => {
      logApp.error('Stream error in chatbot proxy', { cause: error });
      if (!res.headersSent) {
        const { message } = (error as Error);
        res.status(500).send({
          status: 'error',
          error: message,
        });
      } else {
        res.end();
      }
    });
  } catch (e: unknown) {
    logApp.error('Error in chatbot proxy', { cause: e });
    const { message } = (e as Error);

    if (axios.isAxiosError(e) && e.response) {
      res.status(e.response.status).send({
        status: e.response.status,
        error: message,
      });
    } else {
      res.status(503).send({
        status: 503,
        error: message,
      });
    }
    setCookieError(res, message);
  }
};
