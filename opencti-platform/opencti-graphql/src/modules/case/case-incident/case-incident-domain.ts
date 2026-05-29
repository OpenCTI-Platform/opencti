import type { AuthContext, AuthUser } from '../../../types/user';
import { createEntity, updateAttribute } from '../../../database/middleware';
import type { EntityOptions } from '../../../database/middleware-loader';
import { internalLoadById, pageEntitiesConnection, storeLoadById } from '../../../database/middleware-loader';
import { BUS_TOPICS } from '../../../config/conf';
import { ABSTRACT_STIX_DOMAIN_OBJECT, buildRefRelationKey } from '../../../schema/general';
import { notify } from '../../../database/redis';
import { now } from '../../../utils/format';
import { resolveUserIndividual } from '../../../domain/user';
import { isEmptyField } from '../../../database/utils';
import { upsertTemplateForCase } from '../case-domain';
import type { BasicStoreEntityCaseIncident } from './case-incident-types';
import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT } from './case-incident-types';
import type { DomainFindById } from '../../../domain/domainTypes';
import type { CaseIncidentAddInput } from '../../../generated/graphql';
import { EditOperation, FilterMode } from '../../../generated/graphql';
import { isStixId } from '../../../schema/schemaUtils';
import { RELATION_OBJECT } from '../../../schema/stixRefRelationship';
import { FunctionalError } from '../../../config/errors';
import type { BasicStoreEntityCustomFieldDefinition } from '../../customField/custom-field-types';
import { ENTITY_TYPE_CUSTOM_FIELD_DEFINITION } from '../../customField/custom-field-types';

export const findById: DomainFindById<BasicStoreEntityCaseIncident> = (context: AuthContext, user: AuthUser, caseIncidentId: string) => {
  return storeLoadById(context, user, caseIncidentId, ENTITY_TYPE_CONTAINER_CASE_INCIDENT);
};

export const findCaseIncidentPaginated = (context: AuthContext, user: AuthUser, opts: EntityOptions<BasicStoreEntityCaseIncident>) => {
  return pageEntitiesConnection<BasicStoreEntityCaseIncident>(context, user, [ENTITY_TYPE_CONTAINER_CASE_INCIDENT], opts);
};

export const addCaseIncident = async (context: AuthContext, user: AuthUser, caseIncidentAdd: CaseIncidentAddInput) => {
  let caseToCreate = caseIncidentAdd.created ? caseIncidentAdd : { ...caseIncidentAdd, created: now() };
  if (isEmptyField(caseIncidentAdd.createdBy)) {
    const individualId = await resolveUserIndividual(context, user);
    caseToCreate = { ...caseToCreate, createdBy: individualId };
  }
  const { caseTemplates } = caseToCreate;
  delete caseToCreate.caseTemplates;
  const created = await createEntity(context, user, caseToCreate, ENTITY_TYPE_CONTAINER_CASE_INCIDENT);
  if (caseTemplates) {
    await Promise.all(caseTemplates.map((caseTemplate) => upsertTemplateForCase(context, user, created.id, caseTemplate)));
  }
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const caseIncidentContainsStixObjectOrStixRelationship = async (context: AuthContext, user: AuthUser, caseIncidentId: string, thingId: string) => {
  const resolvedThingId = isStixId(thingId) ? (await internalLoadById(context, user, thingId)).internal_id : thingId;
  const args = {
    filters: {
      mode: FilterMode.And,
      filters: [
        { key: ['internal_id'], values: [caseIncidentId] },
        { key: [buildRefRelationKey(RELATION_OBJECT)], values: [resolvedThingId] },
      ],
      filterGroups: [],
    },
  };
  const caseIncidentFound = await findCaseIncidentPaginated(context, user, args);
  return caseIncidentFound.edges.length > 0;
};

export const setCaseIncidentCustomFieldValue = async (context: AuthContext, user: AuthUser, caseIncidentId: string, fieldId: string, value: string) => {
  // Load and validate the CustomFieldDefinition
  const definition = await storeLoadById<BasicStoreEntityCustomFieldDefinition>(context, user, fieldId, ENTITY_TYPE_CUSTOM_FIELD_DEFINITION);
  if (!definition) throw FunctionalError('CustomFieldDefinition not found', { fieldId });
  if (!definition.entity_types?.includes(ENTITY_TYPE_CONTAINER_CASE_INCIDENT)) {
    throw FunctionalError('This custom field is not applicable to Case-Incident', { fieldId });
  }
  // Load current entity to get existing custom_field_values
  const caseIncident = await storeLoadById<BasicStoreEntityCaseIncident>(context, user, caseIncidentId, ENTITY_TYPE_CONTAINER_CASE_INCIDENT);
  if (!caseIncident) throw FunctionalError('CaseIncident not found', { caseIncidentId });
  // eslint-disable-next-line max-len
  const existing: Array<{ field_id: string; field_name: string; int_value?: number; string_value?: string; select_value?: string }> = (caseIncident as any).custom_field_values ?? [];
  const fieldName = `x_opencti_${definition.name}`;
  // Validate and build the new entry based on field_type
  let newEntry: { field_id: string; field_name: string; int_value?: number; string_value?: string; select_value?: string };
  if (definition.field_type === 'integer') {
    const intVal = parseInt(value, 10);
    if (Number.isNaN(intVal)) throw FunctionalError('Value must be an integer', { value });
    if (definition.min_value !== undefined && definition.min_value !== null && intVal < definition.min_value) {
      throw FunctionalError(`Value ${intVal} is below min_value ${definition.min_value}`);
    }
    if (definition.max_value !== undefined && definition.max_value !== null && intVal > definition.max_value) {
      throw FunctionalError(`Value ${intVal} exceeds max_value ${definition.max_value}`);
    }
    newEntry = { field_id: fieldId, field_name: fieldName, int_value: intVal };
  } else if (definition.field_type === 'string') {
    newEntry = { field_id: fieldId, field_name: fieldName, string_value: value };
  } else if (definition.field_type === 'select') {
    if (definition.select_options && definition.select_options.length > 0 && !definition.select_options.includes(value)) {
      throw FunctionalError(`Value "${value}" is not a valid option. Allowed: ${definition.select_options.join(', ')}`);
    }
    newEntry = { field_id: fieldId, field_name: fieldName, select_value: value };
  } else {
    throw FunctionalError(`Unsupported field_type: ${definition.field_type}`, { field_type: definition.field_type });
  }
  const updated = [...existing.filter((v) => v.field_id !== fieldId), newEntry];
  const { element } = await updateAttribute(context, user, caseIncidentId, ENTITY_TYPE_CONTAINER_CASE_INCIDENT, [
    { key: 'custom_field_values', value: updated, operation: EditOperation.Replace },
  ]);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].EDIT_TOPIC, element, user);
};

export const removeCaseIncidentCustomFieldValue = async (context: AuthContext, user: AuthUser, caseIncidentId: string, fieldId: string) => {
  const caseIncident = await storeLoadById<BasicStoreEntityCaseIncident>(context, user, caseIncidentId, ENTITY_TYPE_CONTAINER_CASE_INCIDENT);
  if (!caseIncident) throw FunctionalError('CaseIncident not found', { caseIncidentId });
  const existing: Array<{ field_id: string }> = (caseIncident as any).custom_field_values ?? [];
  const updated = existing.filter((v) => v.field_id !== fieldId);
  const { element } = await updateAttribute(context, user, caseIncidentId, ENTITY_TYPE_CONTAINER_CASE_INCIDENT, [
    { key: 'custom_field_values', value: updated, operation: EditOperation.Replace },
  ]);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].EDIT_TOPIC, element, user);
};
