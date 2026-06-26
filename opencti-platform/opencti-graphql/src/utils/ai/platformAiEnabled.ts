import { FunctionalError } from '../../config/errors';
import { getEntityFromCache } from '../../database/cache';
import { getAiConfigEnabled, setAiEnabledWithOptions } from '../../database/ai-llm';
import { ENTITY_TYPE_SETTINGS } from '../../schema/internalObject';
import type { BasicStoreSettings } from '../../types/settings';
import type { AuthContext } from '../../types/user';
import { SYSTEM_USER } from '../access';
import { AI_DISABLED_ERROR_MESSAGE } from './aiConstants';

export const syncPlatformAiEnabled = async (
  context: AuthContext,
  { initializeClients = false }: { initializeClients?: boolean } = {},
) => {
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const enabled = getAiConfigEnabled() && settings.platform_ai_enabled !== false;
  await setAiEnabledWithOptions(enabled, { initializeClients });
  return enabled;
};

export const checkPlatformAiEnabled = async (context: AuthContext) => {
  const enabled = await syncPlatformAiEnabled(context, { initializeClients: false });
  if (!enabled) {
    throw FunctionalError(AI_DISABLED_ERROR_MESSAGE);
  }
};
