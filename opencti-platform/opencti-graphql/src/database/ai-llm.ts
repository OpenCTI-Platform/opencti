import MistralClient from '@mistralai/mistralai';
import conf, { BUS_TOPICS } from '../config/conf';
import { isEmptyField, isNotEmptyField } from './utils';
import { notify } from './redis';
import { AI_BUS } from '../modules/ai/ai-types';
import type { AuthUser } from '../types/user';

const MISTRALAI_ENDPOINT = conf.get('ai:mistralai:endpoint');
const MISTRALAI_TOKEN = conf.get('ai:mistralai:token');
const MISTRALAI_MODEL = conf.get('ai:mistralai:model');

export const availableEndpoints = () => {
  const endpoints = [];
  if (isNotEmptyField(MISTRALAI_ENDPOINT) && isNotEmptyField(MISTRALAI_TOKEN) && isNotEmptyField(MISTRALAI_MODEL)) {
    endpoints.push(`MistralAI - ${MISTRALAI_MODEL}`);
  }
  return endpoints;
};

const client = new MistralClient(MISTRALAI_TOKEN, isEmptyField(MISTRALAI_ENDPOINT) ? undefined : MISTRALAI_ENDPOINT);

export const listModels = async () => {
  return client.listModels();
};

export const compute = async (busId: string, question: string, user: AuthUser) => {
  const response = client.chatStream({
    model: MISTRALAI_MODEL,
    messages: [{ role: 'user', content: question }],
  });
  let content = '';
  // eslint-disable-next-line no-restricted-syntax
  for await (const chunk of response) {
    if (chunk.choices[0].delta.content !== undefined) {
      const streamText = chunk.choices[0].delta.content;
      content += streamText;
      await notify(BUS_TOPICS[AI_BUS].EDIT_TOPIC, { bus_id: busId, content }, user);
    }
  }
  return content;
};
