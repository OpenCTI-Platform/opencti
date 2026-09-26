import { PLATFORM_VERSION, logApp } from '../../../config/conf';
import { CguStatus } from '../../../generated/graphql';
import type { AuthContext, AuthUser } from '../../../types/user';
import type { BasicStoreSettings } from '../../../types/settings';
import { getEntityFromCache } from '../../../database/cache';
import { ENTITY_TYPE_SETTINGS } from '../../../schema/internalObject';
import { decodeLicensePem, getEnterpriseEditionActivePem, IS_LTS_PLATFORM } from '../../settings/licensing';
import { publishCacheResetEvent, redisGetXtmRegistrationResult, redisSetXtmRegistrationResult } from '../../../database/redis';
import xtmOneClient from './xtm-one-client';
import type { XtmOneRegistrationResponse } from './xtm-one-client';
import { buildXtmLicenseContext, getCurrentXtmLicenseProof, setCurrentXtmLicenseProof, verifyXtmLicenseProof } from './xtm-one-license';
import type { XtmLicenseVerification } from './xtm-one-license';

export const XTM_ONE_SCHEDULE_TIME = 5 * 60 * 1000; // 5 minutes
const XTM_REGISTRATION_RESULT_TTL = Math.ceil((XTM_ONE_SCHEDULE_TIME * 2) / 1000); // 2× schedule, in seconds
const EE_SOURCE_XTM_SUBLICENSE = 'xtm_sublicense';

interface StoredXtmOneRegistration extends XtmOneRegistrationResponse {
  // The warning this answer raised, so that the next heartbeat only logs a change of it.
  xtm_one_entitlement_warning?: string | null;
}

export const getXtmRegistrationResult = async (): Promise<StoredXtmOneRegistration | null> => {
  return await redisGetXtmRegistrationResult() as Promise<StoredXtmOneRegistration | null>;
};

export const getXtmOneRegistrationVersion = async (): Promise<string> => {
  const result = await getXtmRegistrationResult();
  return result?.version ?? 'Not connected';
};

const getXtmOnePlatformId = (settings: BasicStoreSettings) => settings.internal_id || settings.id;

const verifyXtmOneAnswer = (answer: XtmOneRegistrationResponse | null, settings: BasicStoreSettings) => {
  return verifyXtmLicenseProof(answer?.xtm_license_pem, buildXtmLicenseContext(settings, IS_LTS_PLATFORM));
};

/**
 * Load on this node the XTM license of the last registration answer: the proof the Enterprise Edition resolution
 * (getEnterpriseEditionInfo) verifies again on every read. The ee_enabled and ee_sources of the answer are advisory
 * and never grant anything.
 */
export const refreshXtmLicenseProof = async () => {
  try {
    const answer = await getXtmRegistrationResult();
    setCurrentXtmLicenseProof(answer?.xtm_license_pem);
  } catch (error) {
    // Loading the settings must not fail with it: the proof read last is kept, and still verified on every read.
    logApp.warn('[XTM One] Cannot read the XTM license of the last registration', { cause: error });
  }
};

// The Enterprise Edition every node derives from the proof: when it changes, their settings caches are reset so that
// every Enterprise Edition check follows, expiry included.
let publishedXtmLicenseVerdict: string | undefined;
const publishXtmLicenseVerdict = async (settings: BasicStoreSettings) => {
  const verification = verifyXtmLicenseProof(getCurrentXtmLicenseProof(), buildXtmLicenseContext(settings, IS_LTS_PLATFORM));
  const verdict = JSON.stringify([verification.granted, verification.licenseType, verification.validUntil, verification.certificate]);
  if (verdict !== publishedXtmLicenseVerdict) {
    publishedXtmLicenseVerdict = verdict;
    await publishCacheResetEvent(ENTITY_TYPE_SETTINGS);
  }
};

// Only an answer that claims the XTM sub-license path without proving it deserves a warning.
const getXtmOneEntitlementWarning = (answer: XtmOneRegistrationResponse, verification: XtmLicenseVerification, isOwnLicenseValidated: boolean) => {
  if (verification.granted) {
    return undefined;
  }
  if (answer.xtm_license_pem) {
    return `[XTM One] Enterprise Edition not granted by the XTM license: ${verification.reason}. Check the XTM license installed on XTM One`;
  }
  const eeSources = Array.isArray(answer.ee_sources) ? answer.ee_sources : undefined;
  if (eeSources?.includes(EE_SOURCE_XTM_SUBLICENSE)) {
    return '[XTM One] Enterprise Edition not granted by the XTM license: XTM One reports an XTM sub-license without the XTM license certificate proving it';
  }
  if (!eeSources && answer.ee_enabled === true && !isOwnLicenseValidated) {
    return '[XTM One] Enterprise Edition not granted by the XTM license: XTM One reports Enterprise Edition without the Filigran-signed XTM license proving it. '
      + 'Upgrade XTM One to a release returning the XTM license at registration (XTM-One-Platform/xtm-one#3831)';
  }
  return undefined;
};

/**
 * Register this OpenCTI instance with XTM One.
 *
 * Called on every tick by the XTM One registration manager.  The /register
 * endpoint is an upsert so repeated calls are safe and serve as both
 * initial registration and periodic heartbeat. Every answer replaces the
 * XTM license the Enterprise Edition can be granted from: an answer without
 * a proof ends it, an expired proof no longer grants it, and every node
 * recomputes its Enterprise Edition when the outcome changes.
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

  const isOwnLicenseValidated = pem !== undefined && licenseType !== undefined;
  const previousAnswer = await getXtmRegistrationResult();
  const previousVerification = verifyXtmOneAnswer(previousAnswer, settings);
  const isChatbotUsable = settings.filigran_chatbot_ai_cgu_status === CguStatus.Enabled
    && (isOwnLicenseValidated || previousVerification.granted);

  const result = await xtmOneClient.register({
    platform_identifier: 'opencti',
    platform_url: settings.platform_url || '',
    platform_title: settings.platform_title || 'OpenCTI Platform',
    platform_version: PLATFORM_VERSION,
    platform_id: getXtmOnePlatformId(settings),
    enterprise_license_pem: pem,
    license_type: licenseType,
    business_vertical: 'cti',
    // Ask Ariane renders `approval_required` prompts and posts verdicts back
    // through `/chatbot/messages/approve`, so OpenCTI-contributed tools can
    // gate normally instead of needing an administrator to exempt them.
    //
    // Conditional on the assistant actually being reachable — the same CGU and
    // license test `authenticateAndVerify` applies to every chatbot route. The
    // flag is a promise that somebody can be asked; with the panel unusable
    // there is nobody to ask, so gating our tools would only degrade the callers
    // that cannot prompt at all (AI Insights, NLQ search, playbook nodes), which
    // get the plain approval message in place of a result.
    supports_approval_prompts: isChatbotUsable,
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
      { name: 'cti.stix_consumer', description: 'Consume a STIX 2.1 bundle as the final step of an OpenCTI playbook (summarize, alert, post, dispatch)' },
    ],
  });

  if (result) {
    const verification = verifyXtmOneAnswer(result, settings);
    const warning = getXtmOneEntitlementWarning(result, verification, isOwnLicenseValidated) ?? null;
    const storedResult: StoredXtmOneRegistration = { ...result, xtm_one_entitlement_warning: warning };
    await redisSetXtmRegistrationResult(storedResult, XTM_REGISTRATION_RESULT_TTL);
    setCurrentXtmLicenseProof(result.xtm_license_pem);
    logApp.info('[XTM One] Registration successful', {
      status: result.status,
      ee_enabled: result.ee_enabled,
      ee_sources: result.ee_sources,
      xtm_license_enterprise_edition: verification.granted,
      version: result.version,
    });
    // Every heartbeat repeats the answer: its warning is logged when it changes, not every tick.
    if (warning && warning !== previousAnswer?.xtm_one_entitlement_warning) {
      logApp.warn(warning);
    }
  } else {
    logApp.warn('[XTM One] Registration failed, will retry on next tick');
    // The last answer is kept for its TTL: without a new one, the proof lapses with it.
    await refreshXtmLicenseProof();
  }
  await publishXtmLicenseVerdict(settings);
};
