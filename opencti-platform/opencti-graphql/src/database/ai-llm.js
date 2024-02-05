import MistralClient from '@mistralai/mistralai';
import conf from '../config/conf';
import { isNotEmptyField } from './utils';

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

export const client = new MistralClient(MISTRALAI_TOKEN, MISTRALAI_ENDPOINT);

export const query = async (question) => {
  const response = await client.chat({
    model: MISTRALAI_MODEL,
    messages: [{ role: 'user', content: question }],
  });
  return response.choices[0].message.content;
};
