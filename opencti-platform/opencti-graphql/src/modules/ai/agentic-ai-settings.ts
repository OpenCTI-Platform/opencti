import nconf from 'nconf';
import { booleanConf, isFeatureEnabled } from '../../config/conf';

export const getAgenticAiEndpoint = () => {
  return nconf.get('ai:agentic:url');
};

export const isAgenticAiActivated = async () => {
  const isAgenticAiEnabled: boolean = booleanConf('ai:agentic:enabled', true);
  if (!isAgenticAiEnabled) {
    return false;
  }
  const isAgenticFeatureEnabled: boolean = isFeatureEnabled('AGENTIC_AI') || false;
  const isAgenticAiConfigured: boolean = getAgenticAiEndpoint() !== undefined;
  return isAgenticFeatureEnabled && isAgenticAiConfigured;
};
