import type { AuthContext, AuthUser } from '../../../types/user';
import { fullEntitiesList, pageEntitiesConnection, storeLoadById } from '../../../database/middleware-loader';
import { type DefenseLogsourceMappingAddInput, type EditInput, EditOperation, type QueryDefenseLogsourceMappingsArgs } from '../../../generated/graphql';
import { createInternalObject } from '../../../domain/internalObject';
import { deleteElementById, updateAttribute } from '../../../database/middleware';
import { FunctionalError } from '../../../config/errors';
import { publishUserAction } from '../../../listener/UserActionListener';
import { notify } from '../../../database/redis';
import { BUS_TOPICS, logApp } from '../../../config/conf';
import { ABSTRACT_INTERNAL_OBJECT } from '../../../schema/general';
import { now } from '../../../utils/format';
import { buildLogsourceMappingKey } from '../defenseCoverage-utils';
import { requestFullDefenseCoverageComputation } from '../defenseCoverage-state';
import {
  type BasicStoreEntityDefenseLogsourceMapping,
  type DefenseLogsourceMappingDefault,
  ENTITY_TYPE_DEFENSE_LOGSOURCE_MAPPING,
  type StoreEntityDefenseLogsourceMapping,
} from './defenseLogsourceMapping-types';
import defaultMappings from './defenseLogsourceMapping-defaults.json';

export const DEFENSE_LOGSOURCE_MAPPING_DEFAULTS = defaultMappings as DefenseLogsourceMappingDefault[];
const EDITABLE_KEYS = ['data_components', 'active', 'description'];
const MAX_DATA_COMPONENTS = 50;
const MAX_VALUE_LENGTH = 256;

const cleanValue = (value?: string | null) => {
  const cleaned = (value ?? '').trim().toLowerCase();
  if (cleaned.length > MAX_VALUE_LENGTH) {
    throw FunctionalError('Log source value is too long', { length: cleaned.length });
  }
  // The key of a mapping, also its identity, joins the three values with |: a value holding one could take the key of another
  if (cleaned.includes('|')) {
    throw FunctionalError('A log source value cannot contain |', { value: cleaned });
  }
  return cleaned.length > 0 ? cleaned : undefined;
};

const isText = (value: unknown): value is string | null | undefined => value === null || value === undefined || typeof value === 'string';

export const cleanDataComponentNames = (names: ReadonlyArray<unknown>) => {
  if (!names.every(isText)) {
    throw FunctionalError('The data components of a log source mapping must be texts');
  }
  const cleaned = Array.from(new Set(names.map((n) => (n ?? '').trim()).filter((n) => n.length > 0)));
  if (cleaned.length === 0) {
    throw FunctionalError('A log source mapping requires at least one data component');
  }
  if (cleaned.length > MAX_DATA_COMPONENTS || cleaned.some((n) => n.length > MAX_VALUE_LENGTH)) {
    throw FunctionalError('Too many or too long data component names', { count: cleaned.length });
  }
  return cleaned;
};

export const buildLogsourceMappingName = (category?: string, product?: string, service?: string) => {
  return [
    product ? `product: ${product}` : undefined,
    service ? `service: ${service}` : undefined,
    category ? `category: ${category}` : undefined,
  ].filter((p) => !!p).join(', ');
};

const buildMappingInput = (input: DefenseLogsourceMappingDefault & { active?: boolean | null }, builtIn: boolean) => {
  const logsource_category = cleanValue(input.logsource_category);
  const logsource_product = cleanValue(input.logsource_product);
  const logsource_service = cleanValue(input.logsource_service);
  if (!logsource_category && !logsource_product && !logsource_service) {
    throw FunctionalError('A log source mapping requires a category, a product or a service');
  }
  return {
    name: buildLogsourceMappingName(logsource_category, logsource_product, logsource_service),
    description: input.description ?? '',
    mapping_key: buildLogsourceMappingKey(logsource_category, logsource_product, logsource_service),
    x_opencti_rule_logsource: {
      ...(logsource_category ? { category: logsource_category } : {}),
      ...(logsource_product ? { product: logsource_product } : {}),
      ...(logsource_service ? { service: logsource_service } : {}),
    },
    data_components: cleanDataComponentNames(input.data_components),
    active: input.active ?? true,
    built_in: builtIn,
    created_at: now(),
    updated_at: now(),
  };
};

export const findById = (context: AuthContext, user: AuthUser, id: string) => {
  return storeLoadById<BasicStoreEntityDefenseLogsourceMapping>(context, user, id, ENTITY_TYPE_DEFENSE_LOGSOURCE_MAPPING);
};

// The log source columns sort on the fields of the rule log source object the mapping stores
const LOGSOURCE_ORDERING: Record<string, string> = {
  logsource_category: 'x_opencti_rule_logsource.category',
  logsource_product: 'x_opencti_rule_logsource.product',
  logsource_service: 'x_opencti_rule_logsource.service',
};

export const findDefenseLogsourceMappingPaginated = (context: AuthContext, user: AuthUser, args: QueryDefenseLogsourceMappingsArgs) => {
  const orderBy = args.orderBy ? (LOGSOURCE_ORDERING[args.orderBy] ?? args.orderBy) : args.orderBy;
  return pageEntitiesConnection<BasicStoreEntityDefenseLogsourceMapping>(context, user, [ENTITY_TYPE_DEFENSE_LOGSOURCE_MAPPING], { ...args, orderBy });
};

export const listAllDefenseLogsourceMappings = (context: AuthContext, user: AuthUser) => {
  return fullEntitiesList<BasicStoreEntityDefenseLogsourceMapping>(context, user, [ENTITY_TYPE_DEFENSE_LOGSOURCE_MAPPING]);
};

const findByKey = async (context: AuthContext, user: AuthUser, key: string) => {
  const mappings = await listAllDefenseLogsourceMappings(context, user);
  return mappings.find((m) => m.mapping_key === key);
};

export const addDefenseLogsourceMapping = async (context: AuthContext, user: AuthUser, input: DefenseLogsourceMappingAddInput) => {
  const mappingInput = buildMappingInput({
    logsource_category: input.logsource_category ?? undefined,
    logsource_product: input.logsource_product ?? undefined,
    logsource_service: input.logsource_service ?? undefined,
    data_components: input.data_components,
    description: input.description ?? undefined,
    active: input.active,
  }, false);
  const existing = await findByKey(context, user, mappingInput.mapping_key);
  if (existing) {
    throw FunctionalError('A mapping already exists for this log source', { id: existing.id });
  }
  const created = await createInternalObject<StoreEntityDefenseLogsourceMapping>(context, user, mappingInput, ENTITY_TYPE_DEFENSE_LOGSOURCE_MAPPING);
  await requestFullDefenseCoverageComputation();
  return created;
};

// A mapping always keeps between one and MAX_DATA_COMPONENTS data components: an added or removed value, or an object
// path, would change them without that check, so a patch replaces the values of a key as a whole
export const normalizeMappingEditInputs = (input: EditInput[]) => input.map((i) => {
  if ((i.operation && i.operation !== EditOperation.Replace) || i.object_path) {
    throw FunctionalError('A log source mapping is updated by replacing its values, without operation or object path', { key: i.key });
  }
  return i.key === 'data_components' ? { ...i, value: cleanDataComponentNames(i.value) } : i;
});

export const fieldPatchDefenseLogsourceMapping = async (context: AuthContext, user: AuthUser, id: string, input: EditInput[]) => {
  const mapping = await findById(context, user, id);
  if (!mapping) {
    throw FunctionalError(`Log source mapping ${id} cannot be found`);
  }
  const forbidden = input.filter((i) => !EDITABLE_KEYS.includes(i.key));
  if (forbidden.length > 0) {
    throw FunctionalError('Only the data components, the description and the activation of a log source mapping can be updated', {
      keys: forbidden.map((f) => f.key),
    });
  }
  const finalInput = normalizeMappingEditInputs(input);
  const { element } = await updateAttribute<StoreEntityDefenseLogsourceMapping>(context, user, id, ENTITY_TYPE_DEFENSE_LOGSOURCE_MAPPING, finalInput);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${input.map((i) => i.key).join(', ')}\` for log source mapping \`${element.name}\``,
    context_data: { id, entity_type: ENTITY_TYPE_DEFENSE_LOGSOURCE_MAPPING, input },
  });
  await requestFullDefenseCoverageComputation();
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, element, user);
};

export const deleteDefenseLogsourceMapping = async (context: AuthContext, user: AuthUser, id: string) => {
  const mapping = await findById(context, user, id);
  if (!mapping) {
    throw FunctionalError(`Log source mapping ${id} cannot be found`);
  }
  if (mapping.built_in) {
    throw FunctionalError('Built-in log source mappings cannot be deleted, deactivate them instead', { id });
  }
  const deleted = await deleteElementById<StoreEntityDefenseLogsourceMapping>(context, user, id, ENTITY_TYPE_DEFENSE_LOGSOURCE_MAPPING);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `deletes log source mapping \`${deleted.name}\``,
    context_data: { id, entity_type: ENTITY_TYPE_DEFENSE_LOGSOURCE_MAPPING, input: deleted },
  });
  await requestFullDefenseCoverageComputation();
  await notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].DELETE_TOPIC, mapping, user);
  return id;
};

/**
 * Create the built-in mappings that do not exist yet (new platform, or new built-in entries in a release).
 * Existing entries, including the built-in ones edited by an administrator, are kept untouched.
 */
export const initDefenseLogsourceMappings = async (context: AuthContext, user: AuthUser) => {
  const existingKeys = new Set((await listAllDefenseLogsourceMappings(context, user)).map((m) => m.mapping_key));
  let created = 0;
  for (let index = 0; index < DEFENSE_LOGSOURCE_MAPPING_DEFAULTS.length; index += 1) {
    const mappingInput = buildMappingInput(DEFENSE_LOGSOURCE_MAPPING_DEFAULTS[index], true);
    if (!existingKeys.has(mappingInput.mapping_key)) {
      await createInternalObject(context, user, mappingInput, ENTITY_TYPE_DEFENSE_LOGSOURCE_MAPPING, { auditLogEnabled: false });
      existingKeys.add(mappingInput.mapping_key);
      created += 1;
    }
  }
  if (created > 0) {
    logApp.info('[DEFENSE-COVERAGE] Built-in log source mappings created', { created });
    // New mappings can infer telemetry from the log sources of deployed rules: recompute without waiting for the nightly run
    await requestFullDefenseCoverageComputation();
  }
  return created;
};

type RestoreAction = 'create' | 'restore' | 'unchanged' | 'keep_custom';

/**
 * What restoring a built-in mapping does to the mapping holding its log source key: create it when missing, give a
 * built-in entry its shipped definition back, and keep a custom mapping of the same log source (one a later release
 * ships as built-in) untouched - the custom mapping of the organization takes the built-in's place.
 */
export const builtInRestoreAction = (
  current: Pick<BasicStoreEntityDefenseLogsourceMapping, 'built_in' | 'data_components' | 'active' | 'description'> | undefined,
  shipped: { data_components: string[]; description?: string | null },
): RestoreAction => {
  if (!current) return 'create';
  if (!current.built_in) return 'keep_custom';
  const sameComponents = [...current.data_components].sort().join('|') === [...shipped.data_components].sort().join('|');
  return !sameComponents || !current.active || current.description !== shipped.description ? 'restore' : 'unchanged';
};

/**
 * Restore every built-in mapping to its shipped definition and recreate the missing ones.
 * Custom mappings are kept, including one holding the log source of a built-in entry.
 */
export const resetDefenseLogsourceMappings = async (context: AuthContext, user: AuthUser) => {
  const existing = await listAllDefenseLogsourceMappings(context, user);
  const existingByKey = new Map(existing.map((m) => [m.mapping_key, m]));
  let restored = 0;
  for (let index = 0; index < DEFENSE_LOGSOURCE_MAPPING_DEFAULTS.length; index += 1) {
    const mappingInput = buildMappingInput(DEFENSE_LOGSOURCE_MAPPING_DEFAULTS[index], true);
    const current = existingByKey.get(mappingInput.mapping_key);
    const action = builtInRestoreAction(current, mappingInput);
    if (action === 'create') {
      await createInternalObject(context, user, mappingInput, ENTITY_TYPE_DEFENSE_LOGSOURCE_MAPPING, { auditLogEnabled: false });
      restored += 1;
    } else if (action === 'restore' && current) {
      await updateAttribute(context, user, current.id, ENTITY_TYPE_DEFENSE_LOGSOURCE_MAPPING, [
        { key: 'data_components', value: mappingInput.data_components },
        { key: 'active', value: [true] },
        { key: 'description', value: [mappingInput.description] },
      ]);
      restored += 1;
    }
  }
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `resets the built-in log source mappings (${restored} restored)`,
    context_data: { id: ENTITY_TYPE_DEFENSE_LOGSOURCE_MAPPING, entity_type: ENTITY_TYPE_DEFENSE_LOGSOURCE_MAPPING, input: { restored } },
  });
  await requestFullDefenseCoverageComputation();
  return restored;
};
