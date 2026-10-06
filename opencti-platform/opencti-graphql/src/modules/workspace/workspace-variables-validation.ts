import { v4 as uuidv4 } from 'uuid';
import * as R from 'ramda';
import validator from 'validator';
import { FunctionalError } from '../../config/errors';
import { isBasicObject } from '../../schema/stixCoreObject';
import { checkFiltersFormat } from '../../utils/filtering/filtering-utils';
import { containsDashboardVariableToken } from '../dashboard/dashboard-variables-resolution';
import {
  DASHBOARD_VARIABLE_NAME_MAX_LENGTH,
  DASHBOARD_VARIABLE_SELECTION_MAX_VALUES,
  DASHBOARD_VARIABLES_MAX_COUNT,
  type DashboardVariableTypeName,
  type StoreDashboardVariable,
  type StoreDashboardVariableRestriction,
} from './workspace-variables-types';

// Structural shape of the GraphQL DashboardVariableInput (generated enums are string enums).
export interface DashboardVariableInputLike {
  id?: string | null;
  name: string;
  type: string;
  vocabularyCategory?: string | null;
  killChainName?: string | null;
  entityTypes?: string[] | null;
  restriction?: { mode: string; values?: string[] | null; filters?: string | null } | null;
  defaultValue?: string | null;
}

type DistributiveOmit<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never;
type TypeSpecificFields = DistributiveOmit<StoreDashboardVariable, 'id' | 'name' | 'restriction' | 'defaultValue'>;

const buildTypeSpecificFields = (type: DashboardVariableTypeName, input: DashboardVariableInputLike): TypeSpecificFields => {
  if (type !== 'vocabulary' && input.vocabularyCategory) {
    throw FunctionalError('A vocabulary category is only allowed on vocabulary variables');
  }
  if (type !== 'killChainPhase' && input.killChainName) {
    throw FunctionalError('A kill chain name is only allowed on kill chain phase variables');
  }
  if (type !== 'entity' && input.entityTypes && input.entityTypes.length > 0) {
    throw FunctionalError('Entity types are only allowed on entity variables');
  }
  if (type === 'vocabulary') {
    if (!input.vocabularyCategory) throw FunctionalError('A vocabulary variable requires a vocabulary category');
    return { type, vocabularyCategory: input.vocabularyCategory };
  }
  if (type === 'killChainPhase') {
    const killChainName = input.killChainName?.trim();
    if (!killChainName) throw FunctionalError('A kill chain phase variable requires a kill chain name');
    return { type, killChainName };
  }
  if (type === 'entity') {
    const entityTypes = R.uniq(input.entityTypes ?? []);
    if (entityTypes.length === 0) throw FunctionalError('An entity variable requires at least one entity type');
    const unknownTypes = entityTypes.filter((entityType) => !isBasicObject(entityType));
    if (unknownTypes.length > 0) throw FunctionalError('Unknown entity types', { entityTypes: unknownTypes });
    return { type, entityTypes };
  }
  return { type } as TypeSpecificFields;
};

const parseRestrictionFilters = (filters: string) => {
  if (containsDashboardVariableToken(filters)) {
    throw FunctionalError('A variable restriction cannot reference another variable');
  }
  try {
    const parsed = JSON.parse(filters);
    checkFiltersFormat(parsed);
    return parsed;
  } catch {
    throw FunctionalError('Invalid restriction filters');
  }
};

const buildRestriction = (type: DashboardVariableTypeName, input: DashboardVariableInputLike): StoreDashboardVariableRestriction => {
  const restriction = input.restriction ?? { mode: 'none' };
  const hasValues = (restriction.values ?? []).length > 0;
  if (restriction.mode === 'selection') {
    if (restriction.filters) throw FunctionalError('This restriction mode does not accept values or filters');
    const values = R.uniq(restriction.values ?? []);
    if (values.length === 0) throw FunctionalError('A selection restriction requires at least one value');
    if (values.length > DASHBOARD_VARIABLE_SELECTION_MAX_VALUES) {
      throw FunctionalError(`A selection restriction cannot hold more than ${DASHBOARD_VARIABLE_SELECTION_MAX_VALUES} values`);
    }
    return { mode: 'selection', values };
  }
  if (restriction.mode === 'filters') {
    if (type !== 'entity') throw FunctionalError('A filters restriction is only allowed on entity variables');
    if (hasValues || !restriction.filters) throw FunctionalError('Invalid restriction filters');
    return { mode: 'filters', filters: parseRestrictionFilters(restriction.filters) };
  }
  if (hasValues || restriction.filters) throw FunctionalError('This restriction mode does not accept values or filters');
  return { mode: 'none' };
};

const buildDefaultValue = (
  type: DashboardVariableTypeName,
  input: DashboardVariableInputLike,
  restriction: StoreDashboardVariableRestriction,
  now: Date,
) => {
  const raw = input.defaultValue ?? '';
  const isBlank = raw.trim() === '';
  let value = raw;
  if (type === 'boolean') {
    value = isBlank ? 'false' : raw.trim();
    if (value !== 'true' && value !== 'false') throw FunctionalError('A boolean variable default value must be true or false');
  } else if (type === 'date') {
    value = isBlank ? now.toISOString() : raw.trim();
    if (Number.isNaN(Date.parse(value))) throw FunctionalError('A date variable default value must be a valid date');
  } else if (isBlank) {
    throw FunctionalError('Dashboard variable default value is required');
  } else if (type === 'numeric' && !Number.isFinite(Number(raw))) {
    throw FunctionalError('A numeric variable default value must be a number');
  }
  if (restriction.mode === 'selection' && !restriction.values.includes(value)) {
    throw FunctionalError('The default value must belong to the selection');
  }
  return value;
};

/**
 * Validate a GraphQL variable input against the variables already stored in the dashboard
 * and build the variable to store. Throws a FunctionalError on any invalid input.
 */
export const buildDashboardVariable = (
  input: DashboardVariableInputLike,
  existingVariables: StoreDashboardVariable[],
  now: Date = new Date(),
): StoreDashboardVariable => {
  const current = input.id ? existingVariables.find((variable) => variable.id === input.id) : undefined;
  // An unknown id recreates the variable with it: tokens left orphan by a deletion resolve again.
  if (input.id && !current && !validator.isUUID(input.id)) {
    throw FunctionalError('Invalid dashboard variable id', { variableId: input.id });
  }
  if (!current && existingVariables.length >= DASHBOARD_VARIABLES_MAX_COUNT) {
    throw FunctionalError(`A dashboard cannot hold more than ${DASHBOARD_VARIABLES_MAX_COUNT} variables`);
  }
  const name = input.name.trim();
  if (name === '') throw FunctionalError('Dashboard variable name is required');
  if (name.length > DASHBOARD_VARIABLE_NAME_MAX_LENGTH) throw FunctionalError('Dashboard variable name is too long');
  const isDuplicatedName = existingVariables.some((variable) => variable.id !== current?.id
    && variable.name.trim().toLowerCase() === name.toLowerCase());
  if (isDuplicatedName) throw FunctionalError('A dashboard variable with this name already exists', { name });
  const type = input.type as DashboardVariableTypeName;
  if (current && current.type !== type) throw FunctionalError('The type of a dashboard variable cannot be changed');
  const typeSpecificFields = buildTypeSpecificFields(type, input);
  const restriction = buildRestriction(type, input);
  const defaultValue = buildDefaultValue(type, input, restriction, now);
  return { id: input.id ?? uuidv4(), name, ...typeSpecificFields, restriction, defaultValue } as StoreDashboardVariable;
};
