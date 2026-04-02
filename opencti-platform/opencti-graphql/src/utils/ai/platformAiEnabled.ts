import { FunctionalError } from '../../config/errors';
import { getEntityFromCache } from '../../database/cache';
import { setAiEnabledWithOptions } from '../../database/ai-llm';
import { ENTITY_TYPE_SETTINGS } from '../../schema/internalObject';
import type { BasicStoreSettings } from '../../types/settings';
import type { AuthContext } from '../../types/user';
import { SYSTEM_USER } from '../access';

export const syncPlatformAiEnabled = async (
  context: AuthContext,
  { initializeClients = false }: { initializeClients?: boolean } = {},
) => {
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const enabled = settings.platform_ai_enabled !== false;
  await setAiEnabledWithOptions(enabled, { initializeClients });
  return enabled;
};

export const checkPlatformAiEnabled = async (context: AuthContext) => {
  const enabled = await syncPlatformAiEnabled(context, { initializeClients: false });
  if (!enabled) {
    throw FunctionalError('AI is disabled in platform settings');
  }
};
