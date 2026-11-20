import type { AuthContext } from '../types/user';
import { getEntityFromCache } from '../database/cache';
import type { BasicStoreSettings } from '../types/settings';
import { SYSTEM_USER } from '../utils/access';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import { UnsupportedError } from '../config/errors';
import { topEntitiesList } from '../database/middleware-loader';
import { getEnterpriseEditionInfo } from '../modules/settings/licensing';
import { refreshXtmLicenseProof } from '../modules/xtm/one/xtm-one';

export const isEnterpriseEdition = async (context: AuthContext) => {
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  return isEnterpriseEditionFromSettings(settings);
};

// The answer of the database, not of the settings cache: on a cluster the cache of a node follows a license that was just activated
// through pub/sub, and an answer read right after it must already take it into account. valid_enterprise_edition is not stored, it is
// derived by getEnterpriseEditionInfo from the license, as the cache does when it loads, after the same refresh of the XTM license proof.
// Reads the database, so only for rare actions.
export const isEnterpriseEditionUpToDate = async (context: AuthContext) => {
  await refreshXtmLicenseProof();
  const [settings] = await topEntitiesList<BasicStoreSettings>(context, SYSTEM_USER, [ENTITY_TYPE_SETTINGS]);
  return !!settings && getEnterpriseEditionInfo(settings).license_validated;
};

export const isEnterpriseEditionFromSettings = (settings?: Pick<BasicStoreSettings, 'valid_enterprise_edition'>): boolean => {
  return settings?.valid_enterprise_edition === true;
};

export const checkEnterpriseEdition = async (context: AuthContext) => {
  if (!(await isEnterpriseEdition(context))) {
    throw UnsupportedError('Enterprise edition is not enabled');
  }
};
