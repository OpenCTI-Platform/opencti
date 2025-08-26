import nconf from 'nconf';
import axios from 'axios';
import type Express from 'express';
import { createAuthenticatedContext } from './httpAuthenticatedContext';
import { getEntityFromCache } from '../database/cache';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import { getEnterpriseEditionInfo } from '../modules/settings/licensing';
import { logApp } from '../config/conf';
import type { BasicStoreSettings } from '../types/settings';
import { setCookieError } from './httpUtils';

export const getChatbotProxy = async (req: Express.Request, res: Express.Response) => {
  try {
    const context = await createAuthenticatedContext(req, res, 'chatbot');
    if (!context.user) {
      res.sendStatus(403);
      return;
    }

    const chatbotUrl = nconf.get('ai:chatbot:url');
    const isChatbotEnabled = nconf.get('ai:chatbot:enabled');
    const settings = await getEntityFromCache<BasicStoreSettings>(context, context.user, ENTITY_TYPE_SETTINGS);
    const { license_raw_pem } = getEnterpriseEditionInfo(settings);
    if (!isChatbotEnabled || !license_raw_pem) {
      return;
    }
    if (!chatbotUrl) {
      res.status(400).json({ error: 'Chatbot proxy not properly configured' });
      return;
    }

    const vars = {
      OPENCTI_URL: settings.platform_url,
      OPENCTI_TOKEN: context.user?.api_token,
      OPENCTI_CERTIFICATE: Buffer.from(license_raw_pem, 'utf-8').toString('base64'),
    };

    // Enhance headers with url, token and certificate
    const headers = {
      'Content-Type': 'application/json',
      Accept: 'text/event-stream',
      ...vars,
    };

    const enhancedBody = {
      ...req.body,
      overrideConfig: {
        ...req.body.overrideConfig,
        vars: {
          ...req.body.overrideConfig?.vars,
          ...vars,
        }
      }
    };

    // Repost the request to Flowise with enhanced headers and body
    const response = await axios.post(chatbotUrl, enhancedBody, {
      headers,
      responseType: 'stream',
    });

    // Set SSE headers and forward Flowise headers
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('Access-Control-Allow-Origin', '*');
    Object.entries(response.headers).forEach(([key, value]) => {
      if (!['content-length', 'content-encoding'].includes(key.toLowerCase())) {
        res.setHeader(key, value);
      }
    });

    // Pipe the response stream directly to client
    response.data.pipe(res);

    req.on('close', () => {
      response.data.destroy();
    });
  } catch (e: unknown) {
    logApp.error('Error in chatbot proxy', { cause: e });
    const { message } = (e as Error);
    setCookieError(res, message);
    res.status(503).send({
      status: 'error',
      error: message,
    });
  }
};
