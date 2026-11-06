import { createHash } from 'node:crypto';
import jsonCanonicalize from 'canonicalize';
import conf, { INGESTION_DEDUPLICATION_FEATURE_FLAG, isFeatureEnabled, logApp } from '../config/conf';
import { getEntitiesListFromCache } from './cache';
import { getClientBase, redisTx } from './redis';
import { SYSTEM_USER } from '../utils/access';
import { getDraftContext } from '../utils/draftContext';
import type { AuthContext, AuthUser } from '../types/user';
import {
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_COURSE_OF_ACTION,
  ENTITY_TYPE_IDENTITY_SECTOR,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_LOCATION_COUNTRY,
  ENTITY_TYPE_LOCATION_REGION,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_TOOL,
} from '../schema/stixDomainObject';
import { type BasicStoreEntityIngestionDeduplicationRule, ENTITY_TYPE_INGESTION_DEDUPLICATION_RULE } from '../modules/ingestionDeduplication/ingestionDeduplicationRule-types';

// Peripheral types that rarely change: vulnerabilities, indicators and observables must always be imported
export const INGESTION_DEDUPLICATION_ALLOWED_TYPES = [
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_COURSE_OF_ACTION,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_TOOL,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_IDENTITY_SECTOR,
  ENTITY_TYPE_LOCATION_COUNTRY,
  ENTITY_TYPE_LOCATION_REGION,
];

const INGESTION_DEDUPLICATION_TTL = conf.get('ingestion_deduplication:ttl') || 86400;
const NEVER_HASHED_FIELDS = ['clientMutationId'];

// dedup:${stixId} => Redis hash of the last imported content, one field per importing user
const deduplicationKey = (stixId: string) => `dedup:${stixId}`;

export interface IngestionDeduplication {
  key: string;
  userId: string;
  hash: string;
}

export const isIngestionDeduplicationType = (type: string) => {
  return isFeatureEnabled(INGESTION_DEDUPLICATION_FEATURE_FLAG) && INGESTION_DEDUPLICATION_ALLOWED_TYPES.includes(type);
};

export const findIngestionDeduplicationRule = async (context: AuthContext, userId: string, type: string) => {
  const rules = await getEntitiesListFromCache<BasicStoreEntityIngestionDeduplicationRule>(context, SYSTEM_USER, ENTITY_TYPE_INGESTION_DEDUPLICATION_RULE);
  return rules.find((rule) => rule.user_id === userId && rule.target_type === type);
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
  const rule = await findIngestionDeduplicationRule(context, user.id, type);
  if (!rule) {
    return null;
  }
  const excludedFields = new Set([...NEVER_HASHED_FIELDS, ...(rule.excluded_fields ?? [])]);
  const content = Object.fromEntries(Object.entries(input).filter(([field]) => !excludedFields.has(field)));
  const hash = createHash('sha256').update(jsonCanonicalize(content) ?? '').digest('hex');
  return { key: deduplicationKey(input.stix_id), userId: user.id, hash };
};

// Best effort: a Redis failure must never block an import
export const isIngestionUnchanged = async (deduplication: IngestionDeduplication) => {
  try {
    const lastHash = await getClientBase().hget(deduplication.key, deduplication.userId);
    return lastHash === deduplication.hash;
  } catch (err) {
    logApp.warn('[INGESTION DEDUPLICATION] Unable to read the last imported content', { cause: err, key: deduplication.key });
    return false;
  }
};

export const recordIngestion = async (deduplication: IngestionDeduplication) => {
  try {
    await redisTx(getClientBase(), (tx) => {
      tx.hset(deduplication.key, deduplication.userId, deduplication.hash);
      tx.expire(deduplication.key, INGESTION_DEDUPLICATION_TTL);
    });
  } catch (err) {
    logApp.warn('[INGESTION DEDUPLICATION] Unable to record the imported content', { cause: err, key: deduplication.key });
  }
};

export const clearIngestionDeduplication = async (
  context: AuthContext,
  user: AuthUser,
  instances: Array<{ entity_type: string; standard_id?: string; x_opencti_stix_ids?: string[] }>,
) => {
  if (getDraftContext(context, user)) {
    return;
  }
  const stixIds = new Set<string>();
  instances.filter((instance) => isIngestionDeduplicationType(instance.entity_type)).forEach((instance) => {
    if (instance.standard_id) stixIds.add(instance.standard_id);
    (instance.x_opencti_stix_ids ?? []).forEach((stixId) => stixIds.add(stixId));
  });
  if (stixIds.size === 0) {
    return;
  }
  try {
    // One DEL per key: keys of one entity can live in different cluster slots
    await Promise.all(Array.from(stixIds).map((stixId) => getClientBase().del(deduplicationKey(stixId))));
  } catch (err) {
    logApp.warn('[INGESTION DEDUPLICATION] Unable to clear the imported content', { cause: err, ids: Array.from(stixIds) });
  }
};
