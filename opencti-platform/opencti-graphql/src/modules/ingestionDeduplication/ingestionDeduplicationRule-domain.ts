import { type GraphQLSchema, isInputObjectType } from 'graphql';
import { BUS_TOPICS, INGESTION_DEDUPLICATION_FEATURE_FLAG, isFeatureEnabled } from '../../config/conf';
import { FunctionalError } from '../../config/errors';
import { createEntity, deleteElementById, updateAttribute } from '../../database/middleware';
import { fullEntitiesList, storeLoadById } from '../../database/middleware-loader';
import { getEntitiesListFromCache } from '../../database/cache';
import { notify } from '../../database/redis';
import {
  findIngestionDeduplicationRules,
  INGESTION_DEDUPLICATION_ALLOWED_TYPES,
  INGESTION_DEDUPLICATION_DEFAULT_EXCLUDED_FIELDS,
  INGESTION_DEDUPLICATION_TTL,
} from '../../database/ingestionDeduplication';
import { publishUserAction } from '../../listener/UserActionListener';
import { enforceEnableFeatureFlag, SYSTEM_USER } from '../../utils/access';
import type { AuthContext, AuthUser } from '../../types/user';
import { type EditInput, FilterMode, type IngestionDeduplicationRuleAddInput } from '../../generated/graphql';
import { connectorIdFromIngestId } from '../../domain/connector';
import { ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_USER } from '../../schema/internalObject';
import type { CachedConnector } from '../connector/connector-types';
import {
  ENTITY_TYPE_INGESTION_CSV,
  ENTITY_TYPE_INGESTION_JSON,
  ENTITY_TYPE_INGESTION_RSS,
  ENTITY_TYPE_INGESTION_TAXII,
  ENTITY_TYPE_INGESTION_TAXII_COLLECTION,
} from '../ingestion/ingestion-types';
import {
  type BasicStoreEntityIngestionDeduplicationRule,
  ENTITY_TYPE_INGESTION_DEDUPLICATION_RULE,
  type StoreEntityIngestionDeduplicationRule,
} from './ingestionDeduplicationRule-types';

const TOPICS = BUS_TOPICS[ENTITY_TYPE_INGESTION_DEDUPLICATION_RULE];

export { findIngestionDeduplicationRules };

export const findById = (context: AuthContext, user: AuthUser, id: string) => {
  return storeLoadById<BasicStoreEntityIngestionDeduplicationRule>(context, user, id, ENTITY_TYPE_INGESTION_DEDUPLICATION_RULE);
};

export const findAllowedTypes = () => INGESTION_DEDUPLICATION_ALLOWED_TYPES;

export const findDefaultTtl = () => INGESTION_DEDUPLICATION_TTL;

export const findDefaultExcludedFields = () => INGESTION_DEDUPLICATION_DEFAULT_EXCLUDED_FIELDS;

// Technical fields of an add input: they say how to import, not what the entity is
const NOT_CONTENT_INPUT_FIELDS = ['clientMutationId', 'update', 'file', 'files', 'fileMarkings', 'filesMarkings', 'noTriggerImport', 'embedded', 'upsertOperations'];

// The fields of the add mutation input, which is what the platform hashes
export const findHashableFields = (schema: GraphQLSchema, entityType: string) => {
  if (!INGESTION_DEDUPLICATION_ALLOWED_TYPES.includes(entityType)) {
    return [];
  }
  const addInput = schema.getType(`${entityType.replaceAll('-', '')}AddInput`);
  if (!isInputObjectType(addInput)) {
    return [];
  }
  return Object.keys(addInput.getFields()).filter((field) => !NOT_CONTENT_INPUT_FIELDS.includes(field));
};

// Edit values are untyped: numbers sent as strings are accepted, as for any other numeric attribute
const toTtl = (value: unknown) => (typeof value === 'string' && value.trim() !== '' ? Number(value) : value);

const checkTtl = (ttl: unknown) => {
  if (ttl !== null && ttl !== undefined && (!Number.isInteger(ttl) || (ttl as number) <= 0)) {
    throw FunctionalError('The expiration must be a positive number of seconds', { ttl });
  }
};

const checkRule = async (context: AuthContext, userId: string, targetType: string) => {
  if (!INGESTION_DEDUPLICATION_ALLOWED_TYPES.includes(targetType)) {
    throw FunctionalError('Deduplication is not available for this entity type', { target_type: targetType });
  }
  const ruleUser = await storeLoadById(context, SYSTEM_USER, userId, ENTITY_TYPE_USER);
  if (!ruleUser) {
    throw FunctionalError('The user of a deduplication rule must exist', { user_id: userId });
  }
  const userRules = await findIngestionDeduplicationRules(context, userId);
  if (userRules.some((rule) => rule.target_type === targetType)) {
    throw FunctionalError('A deduplication rule already exists for this user and entity type', { user_id: userId, target_type: targetType });
  }
};

export const addIngestionDeduplicationRule = async (context: AuthContext, user: AuthUser, input: IngestionDeduplicationRuleAddInput) => {
  enforceEnableFeatureFlag(INGESTION_DEDUPLICATION_FEATURE_FLAG);
  await checkRule(context, input.user_id, input.target_type);
  checkTtl(input.ttl);
  const ruleInput = { ...input, excluded_fields: input.excluded_fields ?? INGESTION_DEDUPLICATION_DEFAULT_EXCLUDED_FIELDS };
  const element = await createEntity(context, user, ruleInput, ENTITY_TYPE_INGESTION_DEDUPLICATION_RULE) as StoreEntityIngestionDeduplicationRule;
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'administration',
    message: `creates ingestion deduplication rule for \`${element.target_type}\``,
    context_data: { id: element.id, entity_type: ENTITY_TYPE_INGESTION_DEDUPLICATION_RULE, input: ruleInput },
  });
  return notify(TOPICS.ADDED_TOPIC, element, user);
};

export const fieldPatchIngestionDeduplicationRule = async (context: AuthContext, user: AuthUser, id: string, input: EditInput[]) => {
  enforceEnableFeatureFlag(INGESTION_DEDUPLICATION_FEATURE_FLAG);
  const rule = await findById(context, user, id);
  if (!rule) {
    throw FunctionalError(`Ingestion deduplication rule ${id} cannot be found`);
  }
  const allowedKeys = ['excluded_fields', 'ttl'];
  if (input.some((i) => !allowedKeys.includes(i.key))) {
    throw FunctionalError('Only the excluded fields and the expiration of a deduplication rule can be changed');
  }
  const patch = input.map((i) => (i.key === 'ttl' ? { ...i, value: i.value.map(toTtl) } : i));
  patch.filter((i) => i.key === 'ttl').forEach((ttlInput) => ttlInput.value.forEach(checkTtl));
  const { element } = await updateAttribute<StoreEntityIngestionDeduplicationRule>(context, user, id, ENTITY_TYPE_INGESTION_DEDUPLICATION_RULE, patch);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${input.map((i) => i.key).join(', ')}\` for ingestion deduplication rule \`${element.target_type}\``,
    context_data: { id, entity_type: ENTITY_TYPE_INGESTION_DEDUPLICATION_RULE, input },
  });
  return notify(TOPICS.EDIT_TOPIC, element, user);
};

export const deleteIngestionDeduplicationRule = async (context: AuthContext, user: AuthUser, id: string) => {
  enforceEnableFeatureFlag(INGESTION_DEDUPLICATION_FEATURE_FLAG);
  const rule = await findById(context, user, id);
  if (!rule) {
    throw FunctionalError(`Ingestion deduplication rule ${id} cannot be found`);
  }
  const deleted = await deleteElementById<StoreEntityIngestionDeduplicationRule>(context, user, id, ENTITY_TYPE_INGESTION_DEDUPLICATION_RULE);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `deletes ingestion deduplication rule \`${deleted.target_type}\``,
    context_data: { id, entity_type: ENTITY_TYPE_INGESTION_DEDUPLICATION_RULE, input: deleted },
  });
  await notify(TOPICS.DELETE_TOPIC, rule, user);
  return id;
};

export const deleteAllIngestionDeduplicationRulesForUser = async (context: AuthContext, user: AuthUser, userId: string) => {
  if (!isFeatureEnabled(INGESTION_DEDUPLICATION_FEATURE_FLAG)) {
    return;
  }
  const rules = await findIngestionDeduplicationRules(context, userId);
  for (let i = 0; i < rules.length; i += 1) {
    await deleteElementById(context, user, rules[i].id, ENTITY_TYPE_INGESTION_DEDUPLICATION_RULE);
    await notify(TOPICS.DELETE_TOPIC, rules[i], user);
  }
};

// Synchronizations replay stream events, which are never deduplicated
const DEDUPLICATED_FEED_TYPES = [
  ENTITY_TYPE_INGESTION_RSS,
  ENTITY_TYPE_INGESTION_CSV,
  ENTITY_TYPE_INGESTION_JSON,
  ENTITY_TYPE_INGESTION_TAXII,
  ENTITY_TYPE_INGESTION_TAXII_COLLECTION,
];

// Every ingestion running as this user, except the connector being looked at and the feed it is the built-in twin of
export const findUserIngestionUsages = async (context: AuthContext, user: AuthUser, userId: string, excludeConnectorId?: string | null) => {
  const userFilter = { mode: FilterMode.And, filters: [{ key: ['user_id'], values: [userId] }], filterGroups: [] };
  // Loaded as the caller: a feed restricted to other members must not show, even by name
  const [connectors, feeds] = await Promise.all([
    getEntitiesListFromCache<CachedConnector>(context, user, ENTITY_TYPE_CONNECTOR),
    fullEntitiesList(context, user, DEDUPLICATED_FEED_TYPES, { filters: userFilter }),
  ]);
  // Built-in connectors are the twins of feeds, which are listed as such
  const userConnectors = connectors.filter((connector) => !connector.built_in && connector.connector_user_id === userId);
  const isExcluded = (id: string) => !!excludeConnectorId && (id === excludeConnectorId || connectorIdFromIngestId(id) === excludeConnectorId);
  return [...userConnectors, ...feeds]
    .filter((element) => !isExcluded(element.id))
    .map((element) => ({ id: element.id, name: element.name, entity_type: element.entity_type }));
};
