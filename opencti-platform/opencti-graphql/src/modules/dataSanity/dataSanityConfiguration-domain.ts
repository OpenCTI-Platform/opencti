import type { AuthContext, AuthUser } from '../../types/user';
import type { DataSanityConfigurationObject } from './dataSanityConfiguration-types';
import { ENTITY_TYPE_SETTINGS } from '../../schema/internalObject';
import { getEntityFromCache } from '../../database/cache';
import type { BasicStoreSettings } from '../../types/settings';

/**
 * Retrieve the data_sanity_configuration object from the Settings entity.
 */
export const getDataSanityConfigurationFromSettings = async (context: AuthContext, user: AuthUser): Promise<DataSanityConfigurationObject | undefined> => {
  const settings = await getEntityFromCache<BasicStoreSettings>(context, user, ENTITY_TYPE_SETTINGS);
  if (!settings) {
    return undefined;
  }
  return (settings as any).data_sanity_configuration as DataSanityConfigurationObject | undefined;
};
