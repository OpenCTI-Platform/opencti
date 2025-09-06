import nconf from 'nconf';
import { isFeatureEnabled } from '../../config/conf';
import type { BasicStoreSettings } from '../../types/settings';
import { CguStatus } from '../../generated/graphql';

export const getFiligranChatbotAiEndpoint = () => {
  return nconf.get('xtm:one:ai:url');
};

export const isFiligranChatbotAiActivated = async (settings: BasicStoreSettings) => {
  const isChatbotAiEnabled: boolean = settings.filigran_chatbot_ai_cgu_status === CguStatus.Enabled;
  if (!isChatbotAiEnabled) {
    return false;
  }
  const isChatbotFeatureEnabled: boolean = isFeatureEnabled('CHATBOT_AI') || false;
  const isChatbotAiConfigured: boolean = getFiligranChatbotAiEndpoint() !== undefined;
  return isChatbotFeatureEnabled && isChatbotAiConfigured;
};
