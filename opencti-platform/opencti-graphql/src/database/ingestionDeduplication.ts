import { createHash } from 'node:crypto';
import jsonCanonicalize from 'canonicalize';
import { INGESTION_DEDUPLICATION_FEATURE_FLAG, isFeatureEnabled, logApp } from '../config/conf';
import { getEntitiesListFromCache } from './cache';
import { redisGetIngestionRecord, redisSetIngestionRecord } from './redis';
import { SYSTEM_USER } from '../utils/access';
import { getDraftContext } from '../utils/draftContext';
import { generateStandardId } from '../schema/identifier';
import type { AuthContext, AuthUser } from '../types/user';
import {
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_COURSE_OF_ACTION,
  ENTITY_TYPE_DATA_COMPONENT,
  ENTITY_TYPE_DATA_SOURCE,
  ENTITY_TYPE_IDENTITY_INDIVIDUAL,
  ENTITY_TYPE_IDENTITY_SECTOR,
  ENTITY_TYPE_IDENTITY_SYSTEM,
  ENTITY_TYPE_INFRASTRUCTURE,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_LOCATION_CITY,
  ENTITY_TYPE_LOCATION_COUNTRY,
  ENTITY_TYPE_LOCATION_POSITION,
  ENTITY_TYPE_LOCATION_REGION,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_THREAT_ACTOR_GROUP,
  ENTITY_TYPE_TOOL,
} from '../schema/stixDomainObject';
import { ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL } from '../modules/threatActorIndividual/threatActorIndividual-types';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../modules/organization/organization-types';
import { ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA } from '../modules/administrativeArea/administrativeArea-types';
import { ENTITY_TYPE_NARRATIVE } from '../modules/narrative/narrative-types';
import { ENTITY_TYPE_CHANNEL } from '../modules/channel/channel-types';
import { ENTITY_TYPE_LANGUAGE } from '../modules/language/language-types';
import { ENTITY_TYPE_EVENT } from '../modules/event/event-types';
import { type BasicStoreEntityIngestionDeduplicationRule, ENTITY_TYPE_INGESTION_DEDUPLICATION_RULE } from '../modules/ingestionDeduplication/ingestionDeduplicationRule-types';

// SDOs whose standard id comes from plain fields only: vulnerabilities, indicators, observables and containers must always be imported
export const INGESTION_DEDUPLICATION_ALLOWED_TYPES = [
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_COURSE_OF_ACTION,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_TOOL,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_THREAT_ACTOR_GROUP,
  ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL,
  ENTITY_TYPE_INFRASTRUCTURE,
  ENTITY_TYPE_DATA_SOURCE,
  ENTITY_TYPE_DATA_COMPONENT,
  ENTITY_TYPE_NARRATIVE,
  ENTITY_TYPE_CHANNEL,
  ENTITY_TYPE_LANGUAGE,
  ENTITY_TYPE_EVENT,
  ENTITY_TYPE_IDENTITY_SECTOR,
  ENTITY_TYPE_IDENTITY_ORGANIZATION,
  ENTITY_TYPE_IDENTITY_INDIVIDUAL,
  ENTITY_TYPE_IDENTITY_SYSTEM,
  ENTITY_TYPE_LOCATION_REGION,
  ENTITY_TYPE_LOCATION_COUNTRY,
  ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA,
  ENTITY_TYPE_LOCATION_CITY,
  ENTITY_TYPE_LOCATION_POSITION,
];

export const INGESTION_DEDUPLICATION_TTL = 86400;
// Most sources move these dates on every run: hashing them would never let an import be skipped
export const INGESTION_DEDUPLICATION_DEFAULT_EXCLUDED_FIELDS = ['modified', 'x_opencti_modified_at'];
const NEVER_HASHED_FIELDS = ['clientMutationId'];

export interface IngestionDeduplication {
  standardId: string;
  userId: string;
  hash: string;
  ttl: number;
}

export const isIngestionDeduplicationType = (type: string) => {
  return isFeatureEnabled(INGESTION_DEDUPLICATION_FEATURE_FLAG) && INGESTION_DEDUPLICATION_ALLOWED_TYPES.includes(type);
};

export const findIngestionDeduplicationRules = async (context: AuthContext, userId?: string | null) => {
  const rules = await getEntitiesListFromCache<BasicStoreEntityIngestionDeduplicationRule>(context, SYSTEM_USER, ENTITY_TYPE_INGESTION_DEDUPLICATION_RULE);
  return rules
    .filter((rule) => !userId || rule.user_id === userId)
    .sort((a, b) => a.target_type.localeCompare(b.target_type));
};

export const prepareIngestionDeduplication = async (
  context: AuthContext,
  user: AuthUser,
  input: Record<string, any>,
  type: string,
  opts: { fromRule?: string } = {},
): Promise<IngestionDeduplication | null> => {
  if (!isIngestionDeduplicationType(type) || !input.stix_id || opts.fromRule || getDraftContext(context, user)) {
    return null;
  }
  // Uploads are streams: they cannot be hashed
  if (input.file || input.files?.length > 0) {
    return null;
  }
  // Their references are resolved without telling which are missing: a partial import would be recorded
  if (input.upsertOperations?.length > 0) {
    return null;
  }
  // A replayed stream event can be refused as older than a local change, and the record would not know it
  if (context.eventId) {
    return null;
  }
  const rules = await findIngestionDeduplicationRules(context, user.id);
  const rule = rules.find((r) => r.target_type === type);
  if (!rule) {
    return null;
  }
  // Allowed types build their standard id from plain fields only, so the input gives the one the entity gets
  let standardId: string;
  try {
    standardId = generateStandardId(type, input);
  } catch {
    return null;
  }
  const excludedFields = new Set([...NEVER_HASHED_FIELDS, ...(rule.excluded_fields ?? [])]);
  const content = Object.fromEntries(Object.entries(input).filter(([field]) => !excludedFields.has(field)));
  // The rule version is hashed too: keys left while a rule was missing or different must not match
  const ruleVersion = `${rule.id}:${rule.updated_at}`;
  // A synchronized upsert replaces multi-valued fields instead of adding to them: same input, different result
  const synchronized = context.synchronizedUpsert === true;
  // The user's confidence decides what an upsert may overwrite: same input, different result once it moves
  const confidence = user.effective_confidence_level?.overrides?.find((override) => override.entity_type === type)?.max_confidence
    ?? user.effective_confidence_level?.max_confidence ?? null;
  const hash = createHash('sha256').update(jsonCanonicalize({ rule: ruleVersion, synchronized, confidence, input: content }) ?? '').digest('hex');
  return { standardId, userId: user.id, hash, ttl: rule.ttl ?? INGESTION_DEDUPLICATION_TTL };
};

const toUpdatedAt = (updatedAt: Date | string | undefined) => (updatedAt ? new Date(updatedAt).getTime() : Number.NaN);

// Best effort: a Redis failure must never block an import
export const findUnchangedEntity = async <T extends { updated_at?: Date | string }>(
  deduplication: IngestionDeduplication,
  loadEntity: () => Promise<T | null | undefined>,
): Promise<T | undefined> => {
  let lastImport;
  try {
    lastImport = await redisGetIngestionRecord(deduplication.standardId, deduplication.userId);
  } catch (err) {
    logApp.warn('[INGESTION DEDUPLICATION] Unable to read the last imported content', { cause: err, standardId: deduplication.standardId });
    return undefined;
  }
  if (lastImport?.hash !== deduplication.hash) {
    return undefined;
  }
  const entity = await loadEntity();
  // Missing, no longer visible, or changed by anyone since this import: the content of the source must be applied again
  return entity && toUpdatedAt(entity.updated_at) === lastImport.updatedAt ? entity : undefined;
};

export const recordIngestion = async (deduplication: IngestionDeduplication, entity: { updated_at?: Date | string }) => {
  const updatedAt = toUpdatedAt(entity.updated_at);
  if (Number.isNaN(updatedAt)) {
    return;
  }
  try {
    await redisSetIngestionRecord(deduplication.standardId, deduplication.userId, { hash: deduplication.hash, updatedAt }, deduplication.ttl);
  } catch (err) {
    logApp.warn('[INGESTION DEDUPLICATION] Unable to record the imported content', { cause: err, standardId: deduplication.standardId });
  }
};
