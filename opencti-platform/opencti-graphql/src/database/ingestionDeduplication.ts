import { createHash } from 'node:crypto';
import jsonCanonicalize from 'canonicalize';
import conf, { INGESTION_DEDUPLICATION_FEATURE_FLAG, isFeatureEnabled, logApp } from '../config/conf';
import { getEntitiesListFromCache } from './cache';
import { redisDeleteIngestionHashes, redisGetIngestionHash, redisSetIngestionHash } from './redis';
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

export const INGESTION_DEDUPLICATION_TTL: number = conf.get('ingestion_deduplication:ttl') || 86400;
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

const findIngestionDeduplicationRules = async (context: AuthContext) => {
  return getEntitiesListFromCache<BasicStoreEntityIngestionDeduplicationRule>(context, SYSTEM_USER, ENTITY_TYPE_INGESTION_DEDUPLICATION_RULE);
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
  const rules = await findIngestionDeduplicationRules(context);
  const rule = rules.find((r) => r.user_id === user.id && r.target_type === type);
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
  const hash = createHash('sha256').update(jsonCanonicalize({ rule: ruleVersion, input: content }) ?? '').digest('hex');
  return { standardId, userId: user.id, hash, ttl: rule.ttl ?? INGESTION_DEDUPLICATION_TTL };
};

// Best effort: a Redis failure must never block an import
export const isIngestionUnchanged = async (deduplication: IngestionDeduplication) => {
  try {
    const lastHash = await redisGetIngestionHash(deduplication.standardId, deduplication.userId);
    return lastHash === deduplication.hash;
  } catch (err) {
    logApp.warn('[INGESTION DEDUPLICATION] Unable to read the last imported content', { cause: err, standardId: deduplication.standardId });
    return false;
  }
};

export const recordIngestion = async (deduplication: IngestionDeduplication) => {
  try {
    await redisSetIngestionHash(deduplication.standardId, deduplication.userId, deduplication.hash, deduplication.ttl);
  } catch (err) {
    logApp.warn('[INGESTION DEDUPLICATION] Unable to record the imported content', { cause: err, standardId: deduplication.standardId });
  }
};

export const forgetIngestion = async (deduplication: IngestionDeduplication) => {
  try {
    await redisDeleteIngestionHashes([{ standardId: deduplication.standardId, userId: deduplication.userId }]);
  } catch (err) {
    logApp.warn('[INGESTION DEDUPLICATION] Unable to forget the imported content', { cause: err, standardId: deduplication.standardId });
  }
};

export const clearIngestionDeduplication = async (
  context: AuthContext,
  user: AuthUser,
  instances: Array<{ entity_type: string; standard_id?: string }>,
) => {
  // Called while storing stream events: must never throw
  try {
    if (getDraftContext(context, user)) {
      return;
    }
    const dedupInstances = instances.filter((instance) => instance.standard_id && isIngestionDeduplicationType(instance.entity_type));
    if (dedupInstances.length === 0) {
      return;
    }
    // Only users with a rule on the type can have a key: no need to scan Redis
    const rules = await findIngestionDeduplicationRules(context);
    const entries = new Map<string, { standardId: string; userId: string }>();
    dedupInstances.forEach((instance) => {
      rules.filter((rule) => rule.target_type === instance.entity_type).forEach((rule) => {
        const standardId = instance.standard_id as string;
        entries.set(`${standardId}:${rule.user_id}`, { standardId, userId: rule.user_id });
      });
    });
    if (entries.size > 0) {
      await redisDeleteIngestionHashes(Array.from(entries.values()));
    }
  } catch (err) {
    logApp.warn('[INGESTION DEDUPLICATION] Unable to clear the imported content', { cause: err });
  }
};
