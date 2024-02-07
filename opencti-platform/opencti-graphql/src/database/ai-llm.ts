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
      });
      break;
    default:
      throw UnsupportedError('Not supported AI type (currently support: mistralai, openai)', { type: AI_TYPE });
  }
}

export const queryMistralAi = async (busId: string, question: string, user: AuthUser) => {
  if (!client) {
    throw UnsupportedError('Incorrect AI configuration', { enabled: AI_ENABLED, type: AI_TYPE, endpoint: AI_ENDPOINT, model: AI_MODEL });
  }
  try {
    logApp.info('[AI] Querying MistralAI with prompt', { question });
    const response = (client as MistralClient)?.chatStream({
      model: AI_MODEL,
      messages: [{ role: 'user', content: question }],
    });
    let content = '';
    if (response) {
      // eslint-disable-next-line no-restricted-syntax
      for await (const chunk of response) {
        if (chunk.choices[0].delta.content !== undefined) {
          const streamText = chunk.choices[0].delta.content;
          content += streamText;
          await notify(BUS_TOPICS[AI_BUS].EDIT_TOPIC, { bus_id: busId, content }, user);
        }
      }
      return content;
    }
    logApp.error('[AI] No response from MistralAI', { busId, question });
    return '';
  } catch (err) {
    logApp.error('[AI] Cannot query MistralAI', { error: err });
    return '';
  }
};

export const queryChatGpt = async (busId: string, question: string, user: AuthUser) => {
  if (!client) {
    throw UnsupportedError('Incorrect AI configuration', { enabled: AI_ENABLED, type: AI_TYPE, endpoint: AI_ENDPOINT, model: AI_MODEL });
  }
  try {
    logApp.info('[AI] Querying OpenAI with prompt', { question });
    const response = await (client as OpenAI)?.chat.completions.create({
      model: AI_MODEL,
      messages: [{ role: 'user', content: question }],
      stream: true,
    });
    let content = '';
    if (response) {
      // eslint-disable-next-line no-restricted-syntax
      for await (const chunk of response) {
        if (chunk.choices[0].delta.content !== undefined) {
          const streamText = chunk.choices[0].delta.content;
          content += streamText;
          await notify(BUS_TOPICS[AI_BUS].EDIT_TOPIC, { bus_id: busId, content }, user);
        }
      }
      return content;
    }
    logApp.error('[AI] No response from OpenAI', { busId, question });
    return '';
  } catch (err) {
    logApp.error('[AI] Cannot query OpenAI', { error: err });
    return '';
  }
};

export const compute = async (busId: string, question: string, user: AuthUser) => {
  switch (AI_TYPE) {
    case 'mistralai':
      return queryMistralAi(busId, question, user);
    case 'openai':
      return queryChatGpt(busId, question, user);
    default:
      throw UnsupportedError('Not supported AI type', { type: AI_TYPE });
  }
};
