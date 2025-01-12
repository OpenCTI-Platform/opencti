import MistralClient from '@mistralai/mistralai';
import OpenAI from 'openai';
import conf, { BUS_TOPICS, logApp } from '../config/conf';
import { isEmptyField } from './utils';
import { notify } from './redis';
import { AI_BUS } from '../modules/ai/ai-types';
import type { AuthUser } from '../types/user';
import { UnsupportedError } from '../config/errors';

const AI_ENABLED = conf.get('ai:enabled');
const AI_TYPE = conf.get('ai:type');
const AI_ENDPOINT = conf.get('ai:endpoint');
const AI_TOKEN = conf.get('ai:token');
const AI_MODEL = conf.get('ai:model');

let client: MistralClient | OpenAI | null = null;
if (AI_ENABLED && AI_TOKEN) {
  switch (AI_TYPE) {
    case 'mistralai':
      client = new MistralClient(AI_TOKEN, isEmptyField(AI_ENDPOINT) ? undefined : AI_ENDPOINT);
      break;
    case 'openai':
      client = new OpenAI({
        apiKey: AI_TOKEN,
        ...(isEmptyField(AI_ENDPOINT) ? {} : { baseURL: AI_ENDPOINT }),
      });
      break;
    default:
      throw UnsupportedError('Not supported AI type (currently support: mistralai, openai)', { type: AI_TYPE });
  }
}

export const queryMistralAi = async (busId: string | null, systemMessage: string, userMessage: string, user: AuthUser) => {
  if (!client) {
    throw UnsupportedError('Incorrect AI configuration', { enabled: AI_ENABLED, type: AI_TYPE, endpoint: AI_ENDPOINT, model: AI_MODEL });
  }
  try {
    logApp.debug('[AI] Querying MistralAI with prompt', { questionStart: userMessage.substring(0, 100) });
    const response = (client as MistralClient)?.chatStream({
      model: AI_MODEL,
      messages: [
        { role: 'system', content: systemMessage },
        { role: 'user', content: userMessage }
      ],
    });
    let content = '';
    if (response) {
      // eslint-disable-next-line no-restricted-syntax
      for await (const chunk of response) {
        if (chunk.choices[0].delta.content !== undefined) {
          const streamText = chunk.choices[0].delta.content;
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
    logApp.info('[AI] Querying OpenAI with prompt');
    const response = await (client as OpenAI)?.chat.completions.create({
      model: AI_MODEL,
      messages: [
        { role: 'developer', content: developerMessage },
        { role: 'user', content: userMessage }
      ],
      stream: true,
    });
    let content = '';
    if (response) {
      // eslint-disable-next-line no-restricted-syntax
      for await (const chunk of response) {
        if (chunk.choices[0].delta.content !== undefined) {
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
    case 'openai':
      return queryChatGpt(busId, finalDeveloperMessage, userMessage, user);
    default:
      throw UnsupportedError('Not supported AI type', { type: AI_TYPE });
  }
};
