import type { AuthContext, AuthUser } from '../../../types/user';
import { createEntity } from '../../../database/middleware';
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
import { isStixId } from '../../../schema/schemaUtils';
import { RELATION_OBJECT } from '../../../schema/stixRefRelationship';
import { FilterMode } from '../../../generated/graphql';
import { validateCustomFieldValues } from '../../customField/custom-field-validator';
import type { CustomFieldValue } from '../../customField/custom-field-types';
import { enforceEnableFeatureFlag } from '../../../utils/access';
import { CUSTOM_FIELDS_FEATURE_FLAG } from '../../../config/conf';

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
  // Validate custom field values if provided
  if (caseIncidentAdd.customFieldValues && caseIncidentAdd.customFieldValues.length > 0) {
    enforceEnableFeatureFlag(CUSTOM_FIELDS_FEATURE_FLAG);
    // Normalize GraphQL input (explicit null allowed) to the internal CustomFieldValue shape (undefined only)
    const customFieldValues: CustomFieldValue[] = caseIncidentAdd.customFieldValues.map((v) => ({
      field_id: v.field_id,
      field_name: v.field_name,
      int_value: v.int_value ?? undefined,
      string_value: v.string_value ?? undefined,
      boolean_value: v.boolean_value ?? undefined,
      date_value: v.date_value ?? undefined,
      select_value: v.select_value ?? undefined,
    }));
    validateCustomFieldValues(customFieldValues, ENTITY_TYPE_CONTAINER_CASE_INCIDENT);
    (caseToCreate as any).custom_field_values = customFieldValues;
  }
  // The GraphQL input uses camelCase (customFieldValues) but the store attribute is custom_field_values;
  // remove the raw camelCase key so it isn't sent to indexing (ES strict mapping rejects unknown fields).
  delete (caseToCreate as any).customFieldValues;
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
