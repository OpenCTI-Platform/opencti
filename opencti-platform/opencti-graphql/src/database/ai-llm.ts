import { Mistral } from '@mistralai/mistralai';
import { AzureOpenAI, OpenAI } from 'openai';
import conf, { BUS_TOPICS, logApp } from '../config/conf';
import { isEmptyField } from './utils';
import { notify } from './redis';
import { AI_BUS } from '../modules/ai/ai-types';
import type { AuthUser } from '../types/user';
import { UnsupportedError } from '../config/errors';
import { truncate } from '../utils/format';

const AI_ENABLED = conf.get('ai:enabled');
const AI_TYPE = conf.get('ai:type');
const AI_ENDPOINT = conf.get('ai:endpoint');
const AI_TOKEN = conf.get('ai:token');
const AI_MODEL = conf.get('ai:model');
const AI_MAX_TOKENS = conf.get('ai:max_tokens');
const AI_VERSION = conf.get('ai:version');

let client: Mistral | OpenAI | AzureOpenAI | null = null;
if (AI_ENABLED && AI_TOKEN) {
  switch (AI_TYPE) {
    case 'mistralai':
      client = new Mistral({
        serverURL: isEmptyField(AI_ENDPOINT) ? undefined : AI_ENDPOINT,
        apiKey: AI_TOKEN,
        /* uncomment if you need low level debug on AI
        debugLogger: {
          log: (message, args) => logApp.info(`[AI] log ${message}`, { message }),
          group: (label) => logApp.info(`[AI] group ${label} start.`),
          groupEnd: () => logApp.info('[AI] group end.'),
        } */
      });
      break;
    case 'openai':
      client = new OpenAI({
        apiKey: AI_TOKEN,
        ...(isEmptyField(AI_ENDPOINT) ? {} : { baseURL: AI_ENDPOINT }),
      });
      break;
    case 'azureopenai':
      client = new AzureOpenAI({
        apiKey: AI_TOKEN,
        ...(isEmptyField(AI_ENDPOINT) ? {} : { baseURL: AI_ENDPOINT }),
        ...(isEmptyField(AI_VERSION) ? {} : { apiVersion: AI_VERSION }),
      });
      break;
    default:
      throw UnsupportedError('Not supported AI type (currently support: mistralai, openai, azureopenai)', { type: AI_TYPE });
  }
}

export const queryMistralAi = async (busId: string | null, systemMessage: string, userMessage: string, user: AuthUser) => {
  if (!client) {
    throw UnsupportedError('Incorrect AI configuration', { enabled: AI_ENABLED, type: AI_TYPE, endpoint: AI_ENDPOINT, model: AI_MODEL });
  }
  try {
    logApp.debug('[AI] Querying MistralAI with prompt', { questionStart: userMessage.substring(0, 100) });
    const response = await (client as Mistral)?.chat.stream({
      model: AI_MODEL,
      messages: [
        { role: 'system', content: systemMessage },
        { role: 'user', content: truncate(userMessage, AI_MAX_TOKENS, false) }
      ],
    });
    let content = '';
    if (response) {
      // eslint-disable-next-line no-restricted-syntax
      for await (const chunk of response) {
        if (chunk.data.choices[0].delta.content !== undefined) {
          const streamText = chunk.data.choices[0].delta.content;
          content += streamText;
          if (busId !== null) {
            await notify(BUS_TOPICS[AI_BUS].EDIT_TOPIC, { bus_id: busId, content }, user);
          }
        }
      }
      return content;
    }
    logApp.error('[AI] No response from MistralAI', { busId, systemMessage, userMessage });
    return 'No response from MistralAI';
  } catch (err) {
    logApp.error('[AI] Cannot query MistralAI', { cause: err });
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-expect-error
    return `An error occurred: ${err.toString()}`;
  }
};

export const queryChatGpt = async (busId: string | null, developerMessage: string, userMessage: string, user: AuthUser) => {
  if (!client) {
    throw UnsupportedError('Incorrect AI configuration', { enabled: AI_ENABLED, type: AI_TYPE, endpoint: AI_ENDPOINT, model: AI_MODEL });
  }
  try {
    logApp.info('[AI] Querying OpenAI with prompt', { type: AI_TYPE });
    const response = await (client as OpenAI)?.chat.completions.create({
      model: AI_MODEL,
      messages: [
        { role: (AI_TYPE === 'azureopenai') ? 'system' : 'developer', content: developerMessage },
        { role: 'user', content: truncate(userMessage, AI_MAX_TOKENS, false) }
      ],
      stream: true,
    });
    let content = '';
    if (response) {
      // eslint-disable-next-line no-restricted-syntax
      for await (const chunk of response) {
        if (chunk.choices[0]?.delta.content !== undefined) {
          const streamText = chunk.choices[0].delta.content;
          content += streamText;
          if (busId !== null) {
            await notify(BUS_TOPICS[AI_BUS].EDIT_TOPIC, { bus_id: busId, content }, user);
          }
        }
      }
      return content;
    }
    logApp.error('[AI] No response from OpenAI', { busId, developerMessage, userMessage });
    return 'No response from OpenAI';
  } catch (err) {
    logApp.error('[AI] Cannot query OpenAI', { cause: err });
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-expect-error
    return `An error occurred: ${err.toString()}`;
  }
};

export const queryAi = async (busId: string | null, developerMessage: string | null, userMessage: string, user: AuthUser) => {
  const finalDeveloperMessage = developerMessage || 'You are an assistant helping a cyber threat intelligence analyst to better understand cyber threat intelligence data.';
  switch (AI_TYPE) {
    case 'mistralai':
      return queryMistralAi(busId, finalDeveloperMessage, userMessage, user);
    case 'azureopenai':
    case 'openai':
      return queryChatGpt(busId, finalDeveloperMessage, userMessage, user);
    default:
      throw UnsupportedError('Not supported AI type', { type: AI_TYPE });
  }
};
