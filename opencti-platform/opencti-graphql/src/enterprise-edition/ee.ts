import type { AuthContext } from '../types/user';
import { getEntityFromCache } from '../database/cache';
import type { BasicStoreSettings } from '../types/settings';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import { UnsupportedError } from '../config/errors';

export interface EnterpriseEditionGatedModule {
  executionContext: string;
  enterpriseEditionOnly?: boolean;
}

export const isEnterpriseEdition = async (context: AuthContext) => {
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  return isEnterpriseEditionFromSettings(settings);
};

export const isEnterpriseEditionFromSettings = (settings?: Pick<BasicStoreSettings, 'valid_enterprise_edition'>): boolean => {
  return settings?.valid_enterprise_edition === true;
};

export const checkEnterpriseEdition = async (context: AuthContext) => {
  if (!(await isEnterpriseEdition(context))) {
    throw UnsupportedError('Enterprise edition is not enabled');
  }
};

export const isEnterpriseEditionAuthorized = async (module: EnterpriseEditionGatedModule): Promise<boolean> => {
  if (!module.enterpriseEditionOnly) {
    return true;
  }
  return isEnterpriseEdition(executionContext(module.executionContext));
};
