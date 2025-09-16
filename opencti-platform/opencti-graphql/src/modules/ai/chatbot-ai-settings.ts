import nconf from 'nconf';
import { isFeatureEnabled } from '../../config/conf';
import type { BasicStoreSettings } from '../../types/settings';
import { CguStatus } from '../../generated/graphql';

export const getFiligranChatbotAiEndpoint = () => {
  return `${nconf.get('xtm:xtm_one_url')}/chatbot`;
};

export const isFiligranChatbotAiActivated = async (settings: BasicStoreSettings) => {
  const isChatbotFeatureEnabled: boolean = isFeatureEnabled('CHATBOT_AI') || false;
  const isChatbotCGUAccepted: boolean = settings.filigran_chatbot_ai_cgu_status === CguStatus.Enabled;
  const isChatbotAiConfigured: boolean = nconf.get('xtm:one:ai:url') !== undefined;

  return isChatbotFeatureEnabled && isChatbotCGUAccepted && isChatbotAiConfigured;
};
