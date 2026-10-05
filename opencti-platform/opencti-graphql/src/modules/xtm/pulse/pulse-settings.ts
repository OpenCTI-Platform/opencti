import * as R from 'ramda';
import type { BasicStoreSettings } from '../../../types/settings';
import type { AuthContext } from '../../../types/user';
import type { BasicStoreEntity, StoreMarkingDefinition } from '../../../types/store';
import { getEntitiesListFromCache } from '../../../database/cache';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../../schema/stixMetaObject';
import { fullEntitiesThroughRelationsToList } from '../../../database/middleware-loader';
import { RELATION_LOCATED_AT, RELATION_PART_OF } from '../../../schema/stixCoreRelationship';
import { ENTITY_TYPE_IDENTITY_SECTOR, ENTITY_TYPE_LOCATION_COUNTRY, ENTITY_TYPE_LOCATION_REGION } from '../../../schema/stixDomainObject';
import { SYSTEM_USER } from '../../../utils/access';
import { RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../../../schema/stixRefRelationship';
import { INPUT_GRANTED_REFS, INPUT_MARKINGS } from '../../../schema/general';
import type { PulseHubPlatform } from '../hub/xtm-hub-pulse-client';
import type { PulseOperationalState } from './pulse-cache';
import { PulseAccess, PulseMode, PulseRegionBucket, PulseSectorBucket } from '../../../generated/graphql';
import {
  PULSE_CONSENT_VERSION,
  PULSE_FORCED_EXCLUDED_MARKING_DEFINITIONS,
  PULSE_MODE_VALUES,
  PULSE_REGION_BUCKETS,
  PULSE_SCOPE_ENTITY_TYPES,
  PULSE_SECTOR_BUCKETS,
  type PulseModeValue,
  type PulseRegionBucketValue,
  type PulseSectorBucketValue,
  type PulseSettingsValues,
} from './pulse-types';

interface PulseSettingsStore extends BasicStoreSettings {
  pulse_mode?: string;
  pulse_scopes?: string[];
  pulse_excluded_markings?: string[];
  pulse_sector_bucket?: string;
  pulse_region_bucket?: string;
  pulse_consent_version?: string;
  pulse_consent_date?: Date;
  pulse_consent_user_id?: string;
}

const isSectorBucket = (value: unknown): value is PulseSectorBucketValue => PULSE_SECTOR_BUCKETS.includes(value as PulseSectorBucketValue);
const isRegionBucket = (value: unknown): value is PulseRegionBucketValue => PULSE_REGION_BUCKETS.includes(value as PulseRegionBucketValue);

// The preview sends nothing, so it is the mode of every platform until an administrator chooses another one. The
// contribute-only mode of the first builds was consented to like the contribution: it now reads as well.
const readPulseMode = (stored: string | undefined): PulseModeValue => {
  if (stored === 'contribute') return PulseMode.ContributeAndRead;
  return PULSE_MODE_VALUES.includes(stored as PulseModeValue) ? stored as PulseModeValue : PulseMode.Preview;
};

export const readPulseSettings = (settings: BasicStoreSettings): PulseSettingsValues => {
  const store = settings as PulseSettingsStore;
  const mode = readPulseMode(store.pulse_mode);
  const scopes = (store.pulse_scopes ?? PULSE_SCOPE_ENTITY_TYPES).filter((scope) => PULSE_SCOPE_ENTITY_TYPES.includes(scope));
  return {
    mode,
    scopes,
    excludedMarkingIds: store.pulse_excluded_markings ?? [],
    sectorBucket: isSectorBucket(store.pulse_sector_bucket) ? store.pulse_sector_bucket : undefined,
    regionBucket: isRegionBucket(store.pulse_region_bucket) ? store.pulse_region_bucket : undefined,
    consentVersion: store.pulse_consent_version,
    consentDate: store.pulse_consent_date,
    consentUserId: store.pulse_consent_user_id,
  };
};

// The contribution needs the consent of the current version: after an upgrade that changes its text, nothing is sent
// and the platform reads the preview until an administrator accepts the new one.
export const isPulseConsentCurrent = (values: PulseSettingsValues) => values.consentVersion === PULSE_CONSENT_VERSION;

export const isPulseContributing = (values: PulseSettingsValues) => values.mode === PulseMode.ContributeAndRead && isPulseConsentCurrent(values);

// Reciprocity: the full reads need the contribution, and XTM Hub enforces it. A contributing platform whose
// contribution lapsed (XTM Hub answered contribution_required) falls back to the preview until it contributes again.
// XTM Hub answers the full reads to a platform it accepted a contribution from, until the grace period lapses.
export const hasPulseReadAccess = (state: Pick<PulseOperationalState, 'contribution_accepted' | 'contribution_lapsed'>) => {
  return state.contribution_accepted === 'true' && state.contribution_lapsed !== 'true';
};

// A contributing platform reads the full experience once XTM Hub accepted its contribution, and the preview before.
export const getPulseAccess = (values: PulseSettingsValues, registered: boolean, readAccess: boolean): PulseAccess => {
  if (!registered) return PulseAccess.NotConnected;
  if (values.mode === PulseMode.Off) return PulseAccess.Off;
  if (isPulseContributing(values) && readAccess) return PulseAccess.Full;
  return PulseAccess.Preview;
};

export const getPulseHubPlatform = (settings: BasicStoreSettings): PulseHubPlatform | null => {
  if (!settings.xtm_hub_token) {
    return null;
  }
  return { platformId: settings.id, platformToken: settings.xtm_hub_token };
};

export const getPulseBuckets = (values: PulseSettingsValues) => ({
  sector_bucket: values.sectorBucket ?? PulseSectorBucket.Undisclosed,
  region_bucket: values.regionBucket ?? PulseRegionBucket.Undisclosed,
});

// region markings
const markingKey = (marking: StoreMarkingDefinition) => (marking.definition ?? '').toUpperCase();

export const getForcedExcludedMarkings = async (context: AuthContext): Promise<StoreMarkingDefinition[]> => {
  const markings = await getEntitiesListFromCache<StoreMarkingDefinition>(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION);
  return markings.filter((marking) => PULSE_FORCED_EXCLUDED_MARKING_DEFINITIONS.includes(markingKey(marking)));
};

export interface PulseMarkingPolicy {
  knownMarkingIds: Set<string>;
  excludedMarkingIds: Set<string>;
}

export const buildPulseMarkingPolicy = async (context: AuthContext, values: PulseSettingsValues): Promise<PulseMarkingPolicy> => {
  const markings = await getEntitiesListFromCache<StoreMarkingDefinition>(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION);
  const forced = markings.filter((marking) => PULSE_FORCED_EXCLUDED_MARKING_DEFINITIONS.includes(markingKey(marking))).map((marking) => marking.internal_id);
  return {
    knownMarkingIds: new Set(markings.map((marking) => marking.internal_id)),
    excludedMarkingIds: new Set([...forced, ...values.excludedMarkingIds]),
  };
};

export interface PulseContributableCandidate {
  entity_type: string;
  [RELATION_OBJECT_MARKING]?: string[];
  [RELATION_GRANTED_TO]?: string[];
  restricted_members?: Array<unknown>;
}

// An object leaves the platform only when every marking is known and none is excluded, and when its access is not
// restricted to specific members or shared with specific organizations.
export const isPulseContributable = (entity: PulseContributableCandidate, policy: PulseMarkingPolicy, scopes: string[]): boolean => {
  if (!scopes.includes(entity.entity_type)) {
    return false;
  }
  if ((entity.restricted_members ?? []).length > 0 || (entity[RELATION_GRANTED_TO] ?? []).length > 0) {
    return false;
  }
  const markingIds = entity[RELATION_OBJECT_MARKING] ?? [];
  return markingIds.every((markingId) => policy.knownMarkingIds.has(markingId) && !policy.excludedMarkingIds.has(markingId));
};

// A resolved object (the STIX conversion) carries its markings and organizations as entities, not as ids.
export interface PulseResolvedCandidate {
  entity_type: string;
  [INPUT_MARKINGS]?: Array<{ internal_id: string }>;
  [INPUT_GRANTED_REFS]?: Array<{ internal_id: string }>;
  restricted_members?: Array<unknown> | null;
}

export const isPulseResolvedContributable = (instance: PulseResolvedCandidate, policy: PulseMarkingPolicy, scopes: string[]): boolean => {
  return isPulseContributable({
    entity_type: instance.entity_type,
    [RELATION_OBJECT_MARKING]: (instance[INPUT_MARKINGS] ?? []).map((marking) => marking.internal_id),
    [RELATION_GRANTED_TO]: (instance[INPUT_GRANTED_REFS] ?? []).map((organization) => organization.internal_id),
    restricted_members: instance.restricted_members ?? [],
  }, policy, scopes);
};
// endregion

// region buckets suggested from the platform organization
const SECTOR_KEYWORDS: Array<[PulseSectorBucketValue, string[]]> = [
  [PulseSectorBucket.Finance, ['financ', 'bank', 'insurance', 'payment', 'fintech']],
  [PulseSectorBucket.Government, ['government', 'public administration', 'public sector', 'civil administration', 'diplomac']],
  [PulseSectorBucket.Defense, ['defen', 'military', 'armed forces']],
  [PulseSectorBucket.Healthcare, ['health', 'pharma', 'hospital', 'medical', 'biotech']],
  [PulseSectorBucket.EnergyUtilities, ['energy', 'utilit', 'oil', 'gas', 'electric', 'nuclear', 'water']],
  [PulseSectorBucket.Telecommunications, ['telecom', 'communications']],
  [PulseSectorBucket.Technology, ['technolog', 'software', 'information technology', 'cloud', 'semiconductor']],
  [PulseSectorBucket.Manufacturing, ['manufactur', 'industr', 'automotive', 'chemical', 'construction']],
  [PulseSectorBucket.Transportation, ['transport', 'logistic', 'aviation', 'aerospace', 'maritime', 'rail', 'shipping']],
  [PulseSectorBucket.RetailConsumer, ['retail', 'consumer', 'hospitality', 'commerce', 'food', 'entertainment', 'media']],
  [PulseSectorBucket.EducationResearch, ['education', 'research', 'universit', 'academ']],
  [PulseSectorBucket.NonProfit, ['non-profit', 'nonprofit', 'ngo', 'civil society', 'charit']],
];

const REGION_KEYWORDS: Array<[PulseRegionBucketValue, string[]]> = [
  [PulseRegionBucket.MiddleEast, ['middle east', 'western asia', 'gulf']],
  [PulseRegionBucket.NorthAmerica, ['northern america', 'north america']],
  [PulseRegionBucket.LatinAmerica, ['latin america', 'south america', 'central america', 'caribbean']],
  [PulseRegionBucket.Europe, ['europe']],
  [PulseRegionBucket.Africa, ['africa']],
  [PulseRegionBucket.AsiaPacific, ['asia', 'oceania', 'pacific', 'australia']],
];

export const matchSectorBucket = (names: string[]): PulseSectorBucketValue | undefined => {
  const lowered = names.map((name) => name.toLowerCase());
  const match = SECTOR_KEYWORDS.find(([, keywords]) => lowered.some((name) => keywords.some((keyword) => name.includes(keyword))));
  return match?.[0];
};

export const matchRegionBucket = (names: string[]): PulseRegionBucketValue | undefined => {
  const lowered = names.map((name) => name.toLowerCase());
  const match = REGION_KEYWORDS.find(([, keywords]) => lowered.some((name) => keywords.some((keyword) => name.includes(keyword))));
  return match?.[0];
};

export const suggestPulseBuckets = async (context: AuthContext, settings: BasicStoreSettings) => {
  const organizationId = settings.platform_organization;
  if (!organizationId) {
    return { sector: PulseSectorBucket.Undisclosed, region: PulseRegionBucket.Undisclosed };
  }
  const sectors = await fullEntitiesThroughRelationsToList<BasicStoreEntity>(context, SYSTEM_USER, organizationId, RELATION_PART_OF, ENTITY_TYPE_IDENTITY_SECTOR);
  const locations = await fullEntitiesThroughRelationsToList<BasicStoreEntity>(
    context,
    SYSTEM_USER,
    organizationId,
    RELATION_LOCATED_AT,
    [ENTITY_TYPE_LOCATION_COUNTRY, ENTITY_TYPE_LOCATION_REGION],
  );
  const countryIds = locations.filter((location) => location.entity_type === ENTITY_TYPE_LOCATION_COUNTRY).map((location) => location.internal_id);
  const countryRegions = countryIds.length > 0
    ? await fullEntitiesThroughRelationsToList<BasicStoreEntity>(context, SYSTEM_USER, countryIds, RELATION_LOCATED_AT, ENTITY_TYPE_LOCATION_REGION)
    : [];
  const regionNames = R.uniq([...locations, ...countryRegions]
    .filter((location) => location.entity_type === ENTITY_TYPE_LOCATION_REGION)
    .flatMap((region) => [region.name, ...(region.x_opencti_aliases ?? [])])
    .filter((name): name is string => typeof name === 'string'));
  return {
    sector: matchSectorBucket(sectors.map((sector) => sector.name ?? '')) ?? (sectors.length > 0 ? PulseSectorBucket.Other : PulseSectorBucket.Undisclosed),
    region: matchRegionBucket(regionNames) ?? PulseRegionBucket.Undisclosed,
  };
};
// endregion
