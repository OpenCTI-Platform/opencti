import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntityConnector } from '../connector/connector-types';
import { isEnterpriseEdition } from '../../enterprise-edition/ee';
import { HUNT_PLATFORM_INTERNET, HUNT_SCHEDULE_MANUAL, HUNT_SCHEDULE_STANDING, HUNT_TYPE_INDICATORS, HUNT_TYPE_INFRASTRUCTURE, type BasicStoreEntityHunt } from './hunt-types';
import { HUNT_CONFIG, huntSigmaRules, isAutonomousHunt, normalizeNativeQueries, parseHuntFilterGroup } from './hunt-utils';
import { validateHuntSchedule } from './hunt-schedule';
import { huntLogicError, sigmaRuleErrors } from './hunt-validators';
import { HUNT_MESSAGES, type HuntMessageValues, listNames, renderHuntMessage } from './hunt-messages';
import { type HuntIocSet, resolveHuntIocSet } from './hunt-iocs';
import { huntConnectorPlatform, listHuntConnectors, resolveHuntScopePlatforms } from './hunt-dispatch';
import { failedRuleResults, findHuntTranslations, type HuntTranslation, type HuntTranslationSummary, huntTranslationMessage, summarizeHuntTranslations } from './hunt-logic';
import { HuntReadinessKey, HuntReadinessStatus } from '../../generated/graphql';

type ReadinessKey = `${HuntReadinessKey}`;
/** `unmet` blocks the activation, `warning` deserves attention without blocking it. */
type ReadinessStatus = `${HuntReadinessStatus}`;
const KEYS: Record<ReadinessKey, HuntReadinessKey> = {
  logic: HuntReadinessKey.Logic,
  connector: HuntReadinessKey.Connector,
  schedule: HuntReadinessKey.Schedule,
  scope: HuntReadinessKey.Scope,
  draft: HuntReadinessKey.Draft,
  translation: HuntReadinessKey.Translation,
};
const STATUSES: Record<ReadinessStatus, HuntReadinessStatus> = {
  met: HuntReadinessStatus.Met,
  unmet: HuntReadinessStatus.Unmet,
  warning: HuntReadinessStatus.Warning,
};

export interface HuntReadinessItem {
  key: HuntReadinessKey;
  status: HuntReadinessStatus;
  template: string;
  values: { name: string; value: string }[];
  message: string;
}

export interface HuntReadiness {
  ready: boolean;
  items: HuntReadinessItem[];
}

export const isUnmetReadinessItem = (readinessItem: HuntReadinessItem) => readinessItem.status === HuntReadinessStatus.Unmet;

const item = (key: ReadinessKey, status: ReadinessStatus, template: string, values: HuntMessageValues = {}): HuntReadinessItem => ({
  key: KEYS[key],
  status: STATUSES[status],
  template,
  values: Object.entries(values).map(([name, value]) => ({ name, value: String(value) })),
  message: renderHuntMessage(template, values),
});

const logicItems = (hunt: BasicStoreEntityHunt, iocSet: HuntIocSet | null): HuntReadinessItem[] => {
  const rules = huntSigmaRules(hunt);
  const sigmaErrors = rules.flatMap((rule, index) => sigmaRuleErrors(rule).map((error) => (rules.length > 1 ? `rule ${index + 1}: ${error}` : error)));
  if (sigmaErrors.length > 0) {
    return [item('logic', 'unmet', HUNT_MESSAGES.sigmaInvalid, { errors: sigmaErrors.join('; ') })];
  }
  const logicError = huntLogicError(hunt);
  if (logicError) {
    return [item('logic', 'unmet', logicError.message)];
  }
  if (hunt.hunt_type === HUNT_TYPE_INDICATORS && iocSet) {
    if (iocSet.iocs.length === 0) {
      return [item('logic', 'unmet', HUNT_MESSAGES.logicIndicatorsEmpty)];
    }
    const items = [item('logic', 'met', HUNT_MESSAGES.iocCount, { count: iocSet.iocs.length })];
    if (iocSet.truncated) {
      items.push(item('logic', 'warning', HUNT_MESSAGES.iocTruncated, { max: HUNT_CONFIG.maxIocsPerRun }));
    }
    if (iocSet.restricted_count > 0) {
      items.push(item('logic', 'warning', HUNT_MESSAGES.iocRestricted, { count: iocSet.restricted_count }));
    }
    if (iocSet.unsupported_count > 0) {
      items.push(item('logic', 'warning', HUNT_MESSAGES.iocUnsupported, { count: iocSet.unsupported_count }));
    }
    return items;
  }
  const nativePlatforms = normalizeNativeQueries(hunt.native_queries).map((nativeQuery) => nativeQuery.platform);
  if (rules.length === 0) {
    return [item('logic', 'met', HUNT_MESSAGES.nativeQueries, { platforms: listNames(nativePlatforms) })];
  }
  return [rules.length > 1 ? item('logic', 'met', HUNT_MESSAGES.sigmaRulesValid, { count: rules.length }) : item('logic', 'met', HUNT_MESSAGES.sigmaValid)];
};

const scheduleItem = (hunt: BasicStoreEntityHunt, enterprise: boolean): HuntReadinessItem => {
  const schedule = hunt.hunt_schedule || HUNT_SCHEDULE_MANUAL;
  const validation = validateHuntSchedule(schedule, HUNT_CONFIG.minScheduleIntervalMinutes);
  if (!validation.valid) {
    return item('schedule', 'unmet', HUNT_MESSAGES.scheduleInvalid, { error: validation.error ?? schedule });
  }
  if (!enterprise && isAutonomousHunt(hunt)) {
    return item('schedule', 'unmet', HUNT_MESSAGES.scheduleEnterprise);
  }
  if (schedule === HUNT_SCHEDULE_STANDING) {
    return item('schedule', 'met', HUNT_MESSAGES.scheduleStanding);
  }
  if (schedule !== HUNT_SCHEDULE_MANUAL) {
    return item('schedule', 'met', HUNT_MESSAGES.scheduleCron, { schedule });
  }
  return item('schedule', 'met', hunt.hunt_pir_activation ? HUNT_MESSAGES.schedulePir : HUNT_MESSAGES.scheduleManual);
};

const connectorItem = (
  hunt: BasicStoreEntityHunt,
  connectors: BasicStoreEntityConnector[],
  scopePlatformIds: Set<string> | null,
  // Security platforms (empty for the internet) the current logic fails to translate to for good
  untranslatablePlatformIds: Set<string> = new Set(),
): HuntReadinessItem => {
  let candidates: BasicStoreEntityConnector[];
  let missing: string;
  if (hunt.hunt_type === HUNT_TYPE_INFRASTRUCTURE) {
    candidates = connectors.filter((connector) => huntConnectorPlatform(connector) === HUNT_PLATFORM_INTERNET);
    missing = HUNT_MESSAGES.connectorInternetMissing;
  } else {
    const inScope = connectors.filter((connector) => huntConnectorPlatform(connector) !== HUNT_PLATFORM_INTERNET
      && !!connector.hunt_security_platform_id && (scopePlatformIds?.has(connector.hunt_security_platform_id) ?? false));
    if (hunt.hunt_type === HUNT_TYPE_INDICATORS) {
      candidates = inScope.filter((connector) => connector.hunt_supports_indicators === true);
      missing = inScope.length > 0 ? HUNT_MESSAGES.connectorIndicatorsMissing : HUNT_MESSAGES.connectorMissing;
    } else {
      candidates = inScope;
      missing = HUNT_MESSAGES.connectorMissing;
    }
  }
  if (candidates.length === 0) {
    return item('connector', 'unmet', missing);
  }
  const alive = candidates.filter((connector) => connector.active === true);
  if (alive.length === 0) {
    return item('connector', 'warning', HUNT_MESSAGES.connectorUnreachable, { connectors: listNames(candidates.map((connector) => connector.name)) });
  }
  // A connector that cannot translate the logic for its platform cannot run it
  const translating = alive.filter((connector) => !untranslatablePlatformIds.has(connector.hunt_security_platform_id ?? ''));
  if (translating.length === 0) {
    return item('connector', 'unmet', HUNT_MESSAGES.connectorTranslationFailed, { connectors: listNames(alive.map((connector) => connector.name)) });
  }
  return item('connector', 'met', HUNT_MESSAGES.connectorReady, { connectors: listNames(translating.map((connector) => connector.name)) });
};

// The translation of the current logic, as the last translation preview or execution of each platform found it: a logic
// that fails to translate for good on every platform that reported blocks the activation, one that fails on some only
// (or some of its rules) warns with that failure (the rest runs), one being checked warns, one translated informs. A
// Sigma rule no platform translated yet is never reported ready: its translation is unknown.
export const translationItem = (translation: HuntTranslationSummary | null, hunt?: BasicStoreEntityHunt): HuntReadinessItem[] => {
  if (!translation) {
    return hunt && huntSigmaRules(hunt).length > 0 ? [item('translation', 'warning', HUNT_MESSAGES.translationUnknown)] : [];
  }
  if (translation.state !== 'failed' && translation.failedOn.length > 0) {
    const { template, values } = huntTranslationMessage(translation.failedOn[0]);
    return [item('translation', 'warning', template, values)];
  }
  const { template, values } = huntTranslationMessage(translation);
  const statuses: Record<HuntTranslation['state'], ReadinessStatus> = { translated: 'met', checking: 'warning', failed: 'unmet' };
  const status = translation.state === 'translated' && failedRuleResults(translation.run).length > 0 ? 'warning' : statuses[translation.state];
  return [item('translation', status, template, values)];
};

/**
 * What a hunt needs to run, item by item, in the words of the user interface: its logic and its translation, a hunt
 * connector able to run it on a platform of its scope, how it runs (manual, schedule, standing, PIR) and its scope. A
 * hunt is ready to be activated when no item is unmet; the activation refuses it otherwise, with the sentence of the
 * first unmet item.
 */
export const computeHuntReadiness = async (context: AuthContext, user: AuthUser, hunt: BasicStoreEntityHunt): Promise<HuntReadiness> => {
  const logicValid = huntLogicError(hunt) === null;
  const [enterprise, connectors, iocSet, translations] = await Promise.all([
    isEnterpriseEdition(context),
    listHuntConnectors(context, false),
    hunt.hunt_type === HUNT_TYPE_INDICATORS && logicValid ? resolveHuntIocSet(context, hunt) : Promise.resolve(null),
    logicValid ? findHuntTranslations(context, user, hunt) : Promise.resolve([]),
  ]);
  const logic = logicItems(hunt, iocSet);
  const items: HuntReadinessItem[] = [...logic, ...(logic.some(isUnmetReadinessItem) ? [] : translationItem(summarizeHuntTranslations(translations), hunt))];
  const untranslatable = new Set(translations.filter((translation) => translation.state === 'failed').map((translation) => translation.run.security_platform_id ?? ''));
  if (hunt.hunt_type === HUNT_TYPE_INFRASTRUCTURE) {
    items.push(connectorItem(hunt, connectors, null, untranslatable));
    items.push(scheduleItem(hunt, enterprise));
    items.push(item('scope', 'met', HUNT_MESSAGES.scopeInternet));
  } else {
    const platforms = await resolveHuntScopePlatforms(context, user, hunt);
    items.push(connectorItem(hunt, connectors, new Set(platforms.map((platform) => platform.internal_id)), untranslatable));
    items.push(scheduleItem(hunt, enterprise));
    // A scope of every platform names the platforms it covers today, as the scope of the hunt page lists them
    if (parseHuntFilterGroup(hunt.hunt_scope, 'hunt_scope') === null && platforms.length === 0) {
      items.push(item('scope', 'met', HUNT_MESSAGES.scopeAll));
    } else if (platforms.length === 0) {
      items.push(item('scope', 'unmet', HUNT_MESSAGES.scopeEmpty));
    } else {
      items.push(item('scope', 'met', HUNT_MESSAGES.scopePlatforms, { platforms: listNames(platforms.map((platform) => platform.name)) }));
    }
  }
  if (context.draft_context) {
    items.push(item('draft', 'warning', HUNT_MESSAGES.draftWorkspace));
  }
  return { ready: !items.some(isUnmetReadinessItem), items };
};
