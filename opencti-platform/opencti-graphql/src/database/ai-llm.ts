import MistralClient from '@mistralai/mistralai';
import conf, { logApp } from '../config/conf';
import { isEmptyField, isNotEmptyField } from './utils';

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

export const query = async (question: string) => {
  const response = await client.chat({
    model: MISTRALAI_MODEL,
    messages: [{ role: 'user', content: question }],
  });
  return response.choices[0].message.content;
};
