import { ChatOpenAI } from '@langchain/openai';
import type { ChatOpenAIFields } from '@langchain/openai/dist/chat_models';
import conf, { logApp } from '../config/conf';

const AI_ENDPOINT = conf.get('ai:endpoint');
const AI_TOKEN = conf.get('ai:token');
const AI_MODEL = conf.get('ai:model');

export const queryAi = async (prompt: string) => {
  // TODO move client init out of query
  const clientOptions: ChatOpenAIFields = {
    model: AI_MODEL,
    temperature: 0,
    apiKey: AI_TOKEN,
    configuration: {
      baseURL: `${AI_ENDPOINT}/v1`,
    },
  };
  logApp.info('[AI] clientOptions:', { clientOptions });
  const openAiClient = new ChatOpenAI(clientOptions);

  const result = await openAiClient.invoke(prompt);
  logApp.info('[AI] longchain result:', { result });
  return result;
};
