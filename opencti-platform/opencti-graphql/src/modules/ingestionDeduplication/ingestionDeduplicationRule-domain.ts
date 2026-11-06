import { BUS_TOPICS, INGESTION_DEDUPLICATION_FEATURE_FLAG } from '../../config/conf';
import { FunctionalError } from '../../config/errors';
import { createEntity, deleteElementById, updateAttribute } from '../../database/middleware';
import { storeLoadById } from '../../database/middleware-loader';
import { notify } from '../../database/redis';
import { getEntitiesListFromCache } from '../../database/cache';
import { INGESTION_DEDUPLICATION_ALLOWED_TYPES, INGESTION_DEDUPLICATION_TTL } from '../../database/ingestionDeduplication';
import { publishUserAction } from '../../listener/UserActionListener';
import { enforceEnableFeatureFlag, SYSTEM_USER } from '../../utils/access';
import type { AuthContext, AuthUser } from '../../types/user';
import type { EditInput, IngestionDeduplicationRuleAddInput } from '../../generated/graphql';
import { INGESTION_SOURCES } from '../../manager/ingestionHealthManager';
import { connectorIdFromIngestId } from '../../domain/connector';
import { ENTITY_TYPE_CONNECTOR } from '../../schema/internalObject';
import {
  type BasicStoreEntityIngestionDeduplicationRule,
  ENTITY_TYPE_INGESTION_DEDUPLICATION_RULE,
  type StoreEntityIngestionDeduplicationRule,
} from './ingestionDeduplicationRule-types';

const TOPICS = BUS_TOPICS[ENTITY_TYPE_INGESTION_DEDUPLICATION_RULE];

export const findById = (context: AuthContext, user: AuthUser, id: string) => {
  return storeLoadById<BasicStoreEntityIngestionDeduplicationRule>(context, user, id, ENTITY_TYPE_INGESTION_DEDUPLICATION_RULE);
};

export const findIngestionDeduplicationRules = async (context: AuthContext, userId?: string | null) => {
  const rules = await getEntitiesListFromCache<BasicStoreEntityIngestionDeduplicationRule>(context, SYSTEM_USER, ENTITY_TYPE_INGESTION_DEDUPLICATION_RULE);
  return rules
    .filter((rule) => !userId || rule.user_id === userId)
    .sort((a, b) => a.target_type.localeCompare(b.target_type));
};

export const findAllowedTypes = () => INGESTION_DEDUPLICATION_ALLOWED_TYPES;

export const findDefaultTtl = () => INGESTION_DEDUPLICATION_TTL;

const checkTtl = (ttl: unknown) => {
  if (ttl !== null && ttl !== undefined && (!Number.isInteger(ttl) || (ttl as number) <= 0)) {
    throw FunctionalError('The expiration must be a positive number of seconds', { ttl });
  }
};

const checkRule = async (context: AuthContext, userId: string, targetType: string, ruleId?: string) => {
  if (!INGESTION_DEDUPLICATION_ALLOWED_TYPES.includes(targetType)) {
    throw FunctionalError('Deduplication is not available for this entity type', { target_type: targetType });
  }
  const userRules = await findIngestionDeduplicationRules(context, userId);
  if (userRules.some((rule) => rule.target_type === targetType && rule.id !== ruleId)) {
    throw FunctionalError('A deduplication rule already exists for this user and entity type', { user_id: userId, target_type: targetType });
  }
};

export const addIngestionDeduplicationRule = async (context: AuthContext, user: AuthUser, input: IngestionDeduplicationRuleAddInput) => {
  enforceEnableFeatureFlag(INGESTION_DEDUPLICATION_FEATURE_FLAG);
  await checkRule(context, input.user_id, input.target_type);
  checkTtl(input.ttl);
  const ruleInput = { ...input, excluded_fields: input.excluded_fields ?? [] };
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
  const allowedKeys = ['target_type', 'excluded_fields', 'ttl'];
  if (input.some((i) => !allowedKeys.includes(i.key))) {
    throw FunctionalError('Only the entity type, the excluded fields and the expiration of a deduplication rule can be changed');
  }
  const ttlInput = input.find((i) => i.key === 'ttl');
  if (ttlInput) {
    checkTtl(ttlInput.value[0] ?? null);
  }
  const targetTypeInput = input.find((i) => i.key === 'target_type');
  if (targetTypeInput) {
    await checkRule(context, rule.user_id, targetTypeInput.value[0], rule.id);
  }
  const { element } = await updateAttribute<StoreEntityIngestionDeduplicationRule>(context, user, id, ENTITY_TYPE_INGESTION_DEDUPLICATION_RULE, input);
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

// Every ingestion running as this user, except the connector being looked at and the feed it is the built-in twin of
export const findUserIngestionUsages = async (context: AuthContext, userId: string, excludeConnectorId?: string | null) => {
  const usages = [];
  for (let i = 0; i < INGESTION_SOURCES.length; i += 1) {
    const elements = await INGESTION_SOURCES[i].load(context);
    const matching = elements.filter((element) => {
      const isExcluded = !!excludeConnectorId && (element.id === excludeConnectorId || connectorIdFromIngestId(element.id) === excludeConnectorId);
      const { connector_user_id, user_id } = element as { connector_user_id?: string | null; user_id?: string | null };
      const ingestionUserId = element.entity_type === ENTITY_TYPE_CONNECTOR ? connector_user_id : user_id;
      return !isExcluded && ingestionUserId === userId;
    });
    usages.push(...matching.map((element) => ({ id: element.id, name: element.name, entity_type: element.entity_type })));
  }
  return usages;
};
