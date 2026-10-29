import { BUS_TOPICS } from '../../config/conf';
import { FunctionalError } from '../../config/errors';
import { getEntityFromCache } from '../../database/cache';
import { patchAttributeFromLoadedWithRefs, storeLoadByIdWithRefs } from '../../database/middleware';
import { notify } from '../../database/redis';
import type { IngestionHealthSettingsInput } from '../../generated/graphql';
import { publishUserAction } from '../../listener/UserActionListener';
import { ENTITY_TYPE_SETTINGS } from '../../schema/internalObject';
import type { BasicStoreSettings } from '../../types/settings';
import type { StoreEntity } from '../../types/store';
import type { AuthContext, AuthUser } from '../../types/user';
import { toGraphqlIngestionHealthSettings, validateIngestionHealthSettingsInput } from './ingestionHealth-settings';
import type { IngestionHealthSettings } from './ingestionHealth-types';

// The settings are stored in the platform settings, but read and edited through this API only

export const getIngestionHealthSettings = async (context: AuthContext, user: AuthUser) => {
  const settings = await getEntityFromCache<BasicStoreSettings>(context, user, ENTITY_TYPE_SETTINGS);
  return toGraphqlIngestionHealthSettings(settings);
};

export const ingestionHealthSettingsEdit = async (context: AuthContext, user: AuthUser, input: IngestionHealthSettingsInput) => {
  const { id } = await getEntityFromCache<BasicStoreSettings>(context, user, ENTITY_TYPE_SETTINGS);
  const settings = await storeLoadByIdWithRefs<StoreEntity & BasicStoreSettings>(context, user, id, { type: ENTITY_TYPE_SETTINGS });
  if (!settings) {
    throw FunctionalError('Cant find the platform settings', { id });
  }
  await validateIngestionHealthSettingsInput(context, input, settings);
  // Validated above: the codes are known ones
  const ingestionHealthSettings = { ...settings.ingestion_health_settings, ...input } as IngestionHealthSettings;
  // From the loaded settings: patchAttribute would reject the attribute, not updatable through the generic edition
  const { element } = await patchAttributeFromLoadedWithRefs(context, user, settings, { ingestion_health_settings: ingestionHealthSettings });
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${Object.keys(input).join(', ')}\` for \`ingestion health settings\``,
    context_data: { id, entity_type: ENTITY_TYPE_SETTINGS, input },
  });
  // The ingestion health manager reads the settings from the cache, reset by this event
  await notify(BUS_TOPICS[ENTITY_TYPE_SETTINGS].EDIT_TOPIC, element, user);
  return toGraphqlIngestionHealthSettings(element as unknown as BasicStoreSettings);
};
