import { PLATFORM_VERSION, logApp } from '../../../config/conf';
import type { AuthContext, AuthUser } from '../../../types/user';
import type { BasicStoreSettings } from '../../../types/settings';
import { getEntityFromCache } from '../../../database/cache';
import { ENTITY_TYPE_SETTINGS } from '../../../schema/internalObject';
import { decodeLicensePem, getEnterpriseEditionActivePem } from '../../settings/licensing';
import xtmOneClient from './xtm-one-client';
import type { IntentCatalogEntry } from './xtm-one-client';

let discoveredIntentCatalog: IntentCatalogEntry[] = [];

export const getDiscoveredIntentCatalog = (): IntentCatalogEntry[] => discoveredIntentCatalog;

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
      { name: 'global.assistant', description: 'General-purpose assistant for the platform' },
      { name: 'make.it.shorter', description: 'Shorten / summarize content' },
      { name: 'make.it.longer', description: 'Expand / elaborate content' },
      { name: 'fix.spelling', description: 'Fix spelling and grammar' },
      { name: 'change.tone', description: 'Change the tone of content' },
      { name: 'summarize', description: 'Summarize content' },
      { name: 'explain', description: 'Explain content in simple terms' },
      { name: 'cti.container_summary', description: 'Summarize an OpenCTI container (report, grouping, case)' },
      { name: 'cti.containers_digest', description: 'Summarize containers related to an OpenCTI entity' },
      { name: 'cti.entity_activity', description: 'Analyse activity trends of an OpenCTI entity' },
      { name: 'cti.entity_forecast', description: 'Forecast future activity of an OpenCTI entity' },
      { name: 'cti.entity_history', description: 'Summarize internal history of an OpenCTI entity' },
      { name: 'cti.nlq_search', description: 'Translate a natural-language request into OpenCTI search filters' },
    ],
  });

  if (result) {
    if (result.intent_catalog) {
      discoveredIntentCatalog = result.intent_catalog;
      const agentCount = result.intent_catalog.reduce((acc, entry) => acc + entry.agents.length, 0);
      logApp.info('[XTM One] Intent catalog updated', {
        intents: result.intent_catalog.length,
        agents: agentCount,
      });
    }
    logApp.info('[XTM One] Registration successful', {
      status: result.status,
      ee_enabled: result.ee_enabled,
    });
  } else {
    logApp.warn('[XTM One] Registration failed, will retry on next tick');
  }
};
