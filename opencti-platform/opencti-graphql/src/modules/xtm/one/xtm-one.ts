import { PLATFORM_VERSION, logApp } from '../../../config/conf';
import type { AuthContext, AuthUser } from '../../../types/user';
import type { BasicStoreSettings } from '../../../types/settings';
import { getEntityFromCache } from '../../../database/cache';
import { ENTITY_TYPE_SETTINGS } from '../../../schema/internalObject';
import { decodeLicensePem, getEnterpriseEditionActivePem } from '../../settings/licensing';
import { redisGetXtmRegistrationResult, redisSetXtmRegistrationResult } from '../../../database/redis';
import xtmOneClient from './xtm-one-client';
import type { XtmOneRegistrationResponse } from './xtm-one-client';

export const XTM_ONE_SCHEDULE_TIME = 5 * 60 * 1000; // 5 minutes
const XTM_REGISTRATION_RESULT_TTL = Math.ceil((XTM_ONE_SCHEDULE_TIME * 2) / 1000); // 2× schedule, in seconds

export const getXtmRegistrationResult = async (): Promise<XtmOneRegistrationResponse | null> => {
  return await redisGetXtmRegistrationResult() as Promise<XtmOneRegistrationResponse | null>;
};

export const getXtmOneRegistrationVersion = async (): Promise<string> => {
  const result = await getXtmRegistrationResult();
  return result?.version ?? 'Not connected';
};

/**
 * Register this OpenCTI instance with XTM One.
 *
 * Called on every tick by the XTM One registration manager.  The /register
 * endpoint is an upsert so repeated calls are safe and serve as both
 * initial registration and periodic heartbeat.
 *
 * Sends the business vertical and requested intents so that XTM One
 * returns the intent catalog with available agents.
 */
export const registerWithXtmOne = async (context: AuthContext, user: AuthUser): Promise<void> => {
  if (!xtmOneClient.isConfigured()) {
    return;
  }

  const settings = await getEntityFromCache<BasicStoreSettings>(context, user, ENTITY_TYPE_SETTINGS);
  if (!settings) {
    logApp.warn('[XTM One] Cannot register: settings not available');
    return;
  }

  const { pem } = getEnterpriseEditionActivePem(settings);

  let licenseType: string | undefined;
  try {
    const licenseInfo = decodeLicensePem(settings);
    if (licenseInfo.license_validated && licenseInfo.license_type) {
      licenseType = licenseInfo.license_type;
    }
  } catch {
    // license info not available — CE or invalid PEM
  }

  const result = await xtmOneClient.register({
    platform_identifier: 'opencti',
    platform_url: settings.platform_url || '',
    platform_title: settings.platform_title || 'OpenCTI Platform',
    platform_version: PLATFORM_VERSION,
    platform_id: settings.internal_id || settings.id,
    enterprise_license_pem: pem,
    license_type: licenseType,
    business_vertical: 'cti',
    intents: [
      { name: 'global.assistant', description: 'General-purpose assistant' },
      { name: 'global.make_it_shorter', description: 'Shorten / summarize content' },
      { name: 'global.make_it_longer', description: 'Expand / elaborate content' },
      { name: 'global.fix_spelling', description: 'Fix spelling and grammar' },
      { name: 'global.change_tone', description: 'Change the tone of content' },
      { name: 'global.summarize', description: 'Summarize content' },
      { name: 'global.explain', description: 'Explain content in simple terms' },
      { name: 'cti.container_summary', description: 'Summarize an OpenCTI container (report, grouping, case)' },
      { name: 'cti.containers_digest', description: 'Summarize containers related to an OpenCTI entity' },
      { name: 'cti.entity_activity', description: 'Analyse activity trends of an OpenCTI entity' },
      { name: 'cti.entity_forecast', description: 'Forecast future activity of an OpenCTI entity' },
      { name: 'cti.entity_history', description: 'Summarize internal history of an OpenCTI entity' },
      { name: 'cti.nlq_search', description: 'Generate an OpenCTI filter from a natural language query' },
      { name: 'cti.stix_harvester', description: 'Extract cyber threat intelligence from documents into STIX 2.1 bundles' },
      { name: 'cti.stix_transformer', description: 'Transform a STIX 2.1 bundle (enrich, filter, rewrite, normalize) and return a valid STIX 2.1 bundle' },
    ],
  });

  if (result) {
    await redisSetXtmRegistrationResult(result, XTM_REGISTRATION_RESULT_TTL);
    logApp.info('[XTM One] Registration successful', { status: result.status, ee_enabled: result.ee_enabled, version: result.version });
  } else {
    logApp.warn('[XTM One] Registration failed, will retry on next tick');
  }
};
