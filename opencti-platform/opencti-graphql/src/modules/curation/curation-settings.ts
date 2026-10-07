import type { AuthContext, AuthUser } from '../../types/user';
import { FunctionalError } from '../../config/errors';
import { SYSTEM_USER } from '../../utils/access';
import { patchAttribute } from '../../database/middleware';
import { lockResources } from '../../lock/master-lock';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { publishUserAction } from '../../listener/UserActionListener';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { isStixDomainObject, isStixDomainObjectContainer } from '../../schema/stixDomainObject';
import { ENTITY_TYPE_INDICATOR } from '../indicator/indicator-types';
import { ENTITY_TYPE_MANAGER_CONFIGURATION } from '../managerConfiguration/managerConfiguration-types';
import { findByManagerId, getManagerConfigurationFromCache } from '../managerConfiguration/managerConfiguration-domain';
import {
  AUTHORITY_SOURCE_AUTHOR,
  AUTHORITY_SOURCE_CONNECTOR,
  CURATION_DETECTORS,
  CURATION_MANAGER_ID,
  type CurationDetector,
  type CurationSettings,
  type FieldAuthorityRule,
  RELATIONSHIP_CONFLICT_MODES,
  type RelationshipConflictMode,
  type StalenessOverride,
} from './curation-types';
import { DEFAULT_CURATED_ENTITY_TYPES, DEFAULT_CURATION_SETTINGS } from './curation-defaults';

const MAX_FIELD_AUTHORITY_RULES = 200;
const MAX_FIELD_AUTHORITY_SOURCES = 20;

export const isCuratableEntityType = (entityType: string) => {
  return entityType === ENTITY_TYPE_INDICATOR || (isStixDomainObject(entityType) && !isStixDomainObjectContainer(entityType));
};

const TECHNICAL_ATTRIBUTES = ['internal_id', 'standard_id', 'entity_type', 'id', 'created_at', 'updated_at'];

// A field authority rule targets a business attribute of the entity type: never an internal or technical one.
const isAuthorityAttribute = (entityType: string, name: string) => {
  return !!schemaAttributesDefinition.getAttribute(entityType, name) && !name.startsWith('i_') && !TECHNICAL_ATTRIBUTES.includes(name);
};

/** The attributes a field authority rule can target on each curated entity type, with their labels. */
export const curationAuthorityAttributes = (entityTypes: string[]) => {
  return entityTypes.filter(isCuratableEntityType).map((entityType) => ({
    entity_type: entityType,
    attributes: Array.from(schemaAttributesDefinition.getAttributes(entityType).values())
      .filter((attribute) => isAuthorityAttribute(entityType, attribute.name))
      .map((attribute) => ({ name: attribute.name, label: attribute.label ?? attribute.name })),
  }));
};

const clampNumber = (value: unknown, min: number, max: number, fallback: number) => {
  const parsed = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  return Math.min(max, Math.max(min, parsed));
};

const asStringArray = (value: unknown): string[] => (Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string' && v.length > 0) : []);

/**
 * Merge a stored (possibly partial or older) setting with the defaults, coercing every value into its valid range.
 */
export const normalizeCurationSettings = (raw: Partial<CurationSettings> | null | undefined): CurationSettings => {
  const source = { ...DEFAULT_CURATION_SETTINGS, ...(raw ?? {}) };
  const enabledDetectors = asStringArray(source.enabled_detectors)
    .filter((detector): detector is CurationDetector => (CURATION_DETECTORS as readonly string[]).includes(detector));
  const curatedTypes = asStringArray(source.curated_entity_types).filter(isCuratableEntityType);
  const bandMin = clampNumber(source.ambiguous_band_min, 0, 1, DEFAULT_CURATION_SETTINGS.ambiguous_band_min);
  const bandMax = clampNumber(source.ambiguous_band_max, 0, 1, DEFAULT_CURATION_SETTINGS.ambiguous_band_max);
  const mode = (RELATIONSHIP_CONFLICT_MODES as readonly string[]).includes(source.relationship_conflict_mode)
    ? source.relationship_conflict_mode as RelationshipConflictMode
    : DEFAULT_CURATION_SETTINGS.relationship_conflict_mode;
  const staleOverrides: StalenessOverride[] = (Array.isArray(source.stale_overrides) ? source.stale_overrides : [])
    .filter((override) => override && typeof override.entity_type === 'string' && isCuratableEntityType(override.entity_type))
    .map((override) => ({ entity_type: override.entity_type, months: Math.round(clampNumber(override.months, 1, 240, 24)) }));
  const rules: FieldAuthorityRule[] = (Array.isArray(source.field_authority_rules) ? source.field_authority_rules : [])
    .filter((rule) => rule && typeof rule.entity_type === 'string' && typeof rule.attribute === 'string' && Array.isArray(rule.sources))
    .map((rule) => ({
      entity_type: rule.entity_type,
      attribute: rule.attribute,
      sources: rule.sources
        .filter((s) => s && (s.source_type === AUTHORITY_SOURCE_AUTHOR || s.source_type === AUTHORITY_SOURCE_CONNECTOR) && typeof s.source_id === 'string' && s.source_id.length > 0)
        .slice(0, MAX_FIELD_AUTHORITY_SOURCES),
    }))
    .filter((rule) => rule.sources.length > 0)
    .slice(0, MAX_FIELD_AUTHORITY_RULES);
  return {
    curation_enabled: source.curation_enabled !== false,
    enabled_detectors: enabledDetectors,
    // An empty list saved by an administrator examines no type; only a setting that never had the list takes the defaults.
    curated_entity_types: Array.isArray(source.curated_entity_types) ? curatedTypes : DEFAULT_CURATED_ENTITY_TYPES,
    similarity_threshold: clampNumber(source.similarity_threshold, 0.5, 1, DEFAULT_CURATION_SETTINGS.similarity_threshold),
    description_similarity_enabled: source.description_similarity_enabled === true,
    description_similarity_threshold: clampNumber(source.description_similarity_threshold, 0.5, 1, DEFAULT_CURATION_SETTINGS.description_similarity_threshold),
    behavior_threshold: clampNumber(source.behavior_threshold, 0.1, 1, DEFAULT_CURATION_SETTINGS.behavior_threshold),
    proposal_min_confidence: clampNumber(source.proposal_min_confidence, 0, 1, DEFAULT_CURATION_SETTINGS.proposal_min_confidence),
    ambiguous_band_min: Math.min(bandMin, bandMax),
    ambiguous_band_max: Math.max(bandMin, bandMax),
    adjudication_enabled: source.adjudication_enabled === true,
    adjudication_agent_slug: typeof source.adjudication_agent_slug === 'string' && source.adjudication_agent_slug.length > 0 ? source.adjudication_agent_slug : null,
    adjudication_run_as_id: typeof source.adjudication_run_as_id === 'string' && source.adjudication_run_as_id.length > 0 ? source.adjudication_run_as_id : null,
    adjudication_daily_limit: Math.round(clampNumber(source.adjudication_daily_limit, 0, 10000, DEFAULT_CURATION_SETTINGS.adjudication_daily_limit)),
    stale_default_months: Math.round(clampNumber(source.stale_default_months, 1, 240, DEFAULT_CURATION_SETTINGS.stale_default_months)),
    stale_overrides: staleOverrides,
    relationship_conflict_mode: mode,
    merge_record_retention_days: Math.round(clampNumber(source.merge_record_retention_days, 1, 3650, DEFAULT_CURATION_SETTINGS.merge_record_retention_days)),
    digest_enabled: source.digest_enabled === true,
    digest_day: Math.round(clampNumber(source.digest_day, 0, 6, DEFAULT_CURATION_SETTINGS.digest_day)),
    digest_recipient_ids: asStringArray(source.digest_recipient_ids).slice(0, 500),
    field_authority_enabled: source.field_authority_enabled === true,
    field_authority_rules: rules,
    scan_max_entities_per_type: Math.round(clampNumber(source.scan_max_entities_per_type, 100, 100000, DEFAULT_CURATION_SETTINGS.scan_max_entities_per_type)),
    force_scan: source.force_scan === true,
    last_scan_date: source.last_scan_date ?? null,
    last_snapshot_date: source.last_snapshot_date ?? null,
    last_digest_date: source.last_digest_date ?? null,
  };
};

/**
 * Reject invalid field authority rules with an explicit error (normalizeCurationSettings silently drops them).
 */
export const validateFieldAuthorityRules = (rules: FieldAuthorityRule[]) => {
  if (rules.length > MAX_FIELD_AUTHORITY_RULES) {
    throw FunctionalError('Too many field authority rules', { max: MAX_FIELD_AUTHORITY_RULES });
  }
  const seen = new Set<string>();
  rules.forEach((rule) => {
    if (!isCuratableEntityType(rule.entity_type)) {
      throw FunctionalError('Field authority rules only apply to knowledge entity types', { entity_type: rule.entity_type });
    }
    if (!isAuthorityAttribute(rule.entity_type, rule.attribute)) {
      throw FunctionalError('Field authority rules require a business attribute of the entity type', { entity_type: rule.entity_type, attribute: rule.attribute });
    }
    if (rule.sources.length === 0 || rule.sources.length > MAX_FIELD_AUTHORITY_SOURCES) {
      throw FunctionalError('A field authority rule needs between 1 and 20 ordered sources', { entity_type: rule.entity_type, attribute: rule.attribute });
    }
    // Normalization drops an invalid source, and the rule with it: the save would succeed and lose the rule.
    const invalid = rule.sources.find((source) => (source?.source_type !== AUTHORITY_SOURCE_AUTHOR && source?.source_type !== AUTHORITY_SOURCE_CONNECTOR)
      || typeof source.source_id !== 'string' || source.source_id.trim().length === 0);
    if (invalid) {
      throw FunctionalError('Every source of a field authority rule needs a type (author or connector) and an identifier', { entity_type: rule.entity_type, attribute: rule.attribute });
    }
    const key = `${rule.entity_type}|${rule.attribute}`;
    if (seen.has(key)) {
      throw FunctionalError('Only one field authority rule per entity type and attribute', { entity_type: rule.entity_type, attribute: rule.attribute });
    }
    seen.add(key);
  });
};

/**
 * Reject staleness overrides the detection would not use (normalizeCurationSettings drops an override of another type,
 * and the detection reads only the first override of a type).
 */
export const validateStaleOverrides = (overrides: StalenessOverride[]) => {
  const seen = new Set<string>();
  overrides.forEach((override) => {
    if (typeof override?.entity_type !== 'string' || !isCuratableEntityType(override.entity_type)) {
      throw FunctionalError('Staleness overrides only apply to knowledge entity types', { entity_type: override?.entity_type });
    }
    if (seen.has(override.entity_type)) {
      throw FunctionalError('Only one staleness override per entity type', { entity_type: override.entity_type });
    }
    seen.add(override.entity_type);
  });
};

export const getCurationSettings = async (context: AuthContext): Promise<CurationSettings> => {
  const configuration = await getManagerConfigurationFromCache(context, SYSTEM_USER, CURATION_MANAGER_ID);
  return normalizeCurationSettings(configuration?.manager_setting as Partial<CurationSettings> | undefined);
};

const loadCurationConfiguration = async (context: AuthContext) => {
  const configuration = await findByManagerId(context, SYSTEM_USER, CURATION_MANAGER_ID);
  if (!configuration) {
    throw FunctionalError('Curation manager configuration is not initialized');
  }
  return configuration;
};

const withSettingsWriteLock = async <T>(fn: () => Promise<T>): Promise<T> => {
  let lock;
  try {
    lock = await lockResources(['curation-settings-write']);
    return await fn();
  } finally {
    if (lock) {
      await lock.unlock();
    }
  }
};

/**
 * Persist curation settings. Internal bookkeeping (dates, force_scan) can be written by the manager with
 * auditLog=false, user changes are always audited. The settings are one document: writes are serialized and each one
 * reads the document under the lock, so the manager's bookkeeping never writes back a stale copy over a user change.
 */
export const saveCurationSettings = async (
  context: AuthContext,
  user: AuthUser,
  patch: Partial<CurationSettings>,
  opts: { auditLog?: boolean; validate?: (merged: CurationSettings) => void } = {},
): Promise<CurationSettings> => {
  const { configuration, next } = await withSettingsWriteLock(async () => {
    const loaded = await loadCurationConfiguration(context);
    const current = normalizeCurationSettings(loaded.manager_setting as Partial<CurationSettings>);
    opts.validate?.({ ...current, ...patch });
    const merged = normalizeCurationSettings({ ...current, ...patch });
    const { element: updated } = await patchAttribute(context, user, loaded.id, ENTITY_TYPE_MANAGER_CONFIGURATION, { manager_setting: merged });
    await notify(BUS_TOPICS[ENTITY_TYPE_MANAGER_CONFIGURATION].EDIT_TOPIC, updated, user);
    return { configuration: loaded, next: merged };
  });
  if (opts.auditLog !== false) {
    await publishUserAction({
      user,
      event_type: 'mutation',
      event_scope: 'update',
      event_access: 'administration',
      message: `updates \`${Object.keys(patch).join(', ')}\` for curation settings`,
      context_data: { id: configuration.id, entity_type: ENTITY_TYPE_MANAGER_CONFIGURATION, input: patch },
    });
  }
  return next;
};

export const getCurationSettingsId = async (context: AuthContext) => {
  const configuration = await getManagerConfigurationFromCache(context, SYSTEM_USER, CURATION_MANAGER_ID);
  return configuration?.id ?? CURATION_MANAGER_ID;
};

export const getStalenessMonths = (settings: CurationSettings, entityType: string) => {
  return settings.stale_overrides.find((override) => override.entity_type === entityType)?.months ?? settings.stale_default_months;
};
