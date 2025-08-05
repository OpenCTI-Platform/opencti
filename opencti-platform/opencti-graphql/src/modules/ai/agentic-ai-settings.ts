import nconf from 'nconf';
import { booleanConf, isFeatureEnabled, logApp } from '../../config/conf';

export const getAgenticAiEndpoint = () => {
  return nconf.get('ai:agentic:url');
};

export const isAgenticAiActivated = async () => {
  const isAgenticAiEnabled: boolean = booleanConf('ai:agentic:enabled', true);
  if (!isAgenticAiEnabled) {
    logApp.info('[AI] isAgenticAiEnabled false');
    return false;
  }
  const isAgenticFeatureEnabled: boolean = isFeatureEnabled('AGENTIC_AI') || false;
  const isAgenticAiConfigured: boolean = getAgenticAiEndpoint() !== undefined;
  logApp.info(`[AI] isAgenticFeatureEnabled:${isAgenticFeatureEnabled}, isAgenticAiConfigured:${isAgenticAiConfigured}`);
  return isAgenticFeatureEnabled && isAgenticAiConfigured;
};
