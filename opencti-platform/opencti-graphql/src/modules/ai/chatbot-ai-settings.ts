import nconf from 'nconf';
import { booleanConf, isFeatureEnabled } from '../../config/conf';

export const getFiligranChatbotAiEndpoint = () => {
  return nconf.get('ai:chatbot:url');
};

export const isFiligranChatbotAiActivated = async () => {
  const isChatbotAiEnabled: boolean = booleanConf('ai:chatbot:enabled', true);
  if (!isChatbotAiEnabled) {
    return false;
  }
  const isChatbotFeatureEnabled: boolean = isFeatureEnabled('CHATBOT_AI') || false;
  const isChatbotAiConfigured: boolean = getFiligranChatbotAiEndpoint() !== undefined;
  return isChatbotFeatureEnabled && isChatbotAiConfigured;
};
