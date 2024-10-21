import type { AuthContext } from '../types/user';
import { getEntityFromCache } from '../database/cache';
import type { BasicStoreSettings } from '../types/settings';
import { SYSTEM_USER } from './access';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import { isNotEmptyField } from '../database/utils';
import { UnsupportedError } from '../config/errors';

export const isEnterpriseEdition = async (context: AuthContext) => {
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  return isNotEmptyField(settings?.enterprise_edition);
};

export const checkEnterpriseEdition = async (context: AuthContext) => {
  if (!(await isEnterpriseEdition(context))) {
    throw UnsupportedError('Enterprise edition is not enabled');
  }
};
