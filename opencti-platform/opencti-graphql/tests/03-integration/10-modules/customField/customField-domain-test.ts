import { describe, expect, it } from 'vitest';
import { CF_COMMENT_KEY, CF_SCORE_KEY, customFieldDefinitionAdd, findCustomFieldDefinitionsPaginated } from '../../../../src/modules/customField/custom-field-domain';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { type CaseIncidentAddInput, type CustomFieldDefinitionAddInput, FilterMode, FilterOperator } from '../../../../src/generated/graphql';
import { type BasicStoreEntityCaseIncident, ENTITY_TYPE_CONTAINER_CASE_INCIDENT } from '../../../../src/modules/case/case-incident/case-incident-types';
import { type BasicStoreEntityCustomFieldDefinition, ENTITY_TYPE_CUSTOM_FIELD_DEFINITION } from '../../../../src/modules/customField/custom-field-types';
import { addCaseIncident, findCaseIncidentPaginated } from '../../../../src/modules/case/case-incident/case-incident-domain';
import { waitInSec } from '../../../../src/database/utils';
import { getSchemaAttributes } from '../../../../src/domain/attribute';
import { deleteElementById } from '../../../../src/database/middleware';
import { generateFilterKeysSchema } from '../../../../src/domain/filterKeysSchema';
import type { EntityOptions } from '../../../../src/database/middleware-loader';

describe('CustomFieldDefinition — domain coverage', () => {
  let scoreCfField: BasicStoreEntityCustomFieldDefinition;
  let commentCfField: BasicStoreEntityCustomFieldDefinition;
  let caseIncidentOneCustomField: BasicStoreEntityCaseIncident;
  let caseIncidentAllCustomFields: BasicStoreEntityCaseIncident;
  let caseIncidentNoCustomFields: BasicStoreEntityCaseIncident;

  it('should create a CustomFieldDefinition with field_type=integer', async () => {
    const currentCustomFields = await findCustomFieldDefinitionsPaginated(testContext, ADMIN_USER, { first: 50 });
    if (!currentCustomFields.edges.some((cf) => cf.node.id === CF_SCORE_KEY)) {
      const input: CustomFieldDefinitionAddInput = {
        entity_types: [ENTITY_TYPE_CONTAINER_CASE_INCIDENT],
        field_type: 'integer',
        label: 'cf score',
        max_value: 100,
        min_value: 0,
        name: CF_SCORE_KEY,
        mandatory: false,
      };
      scoreCfField = await customFieldDefinitionAdd(testContext, ADMIN_USER, input);
    }
  });

  it('should create a CustomFieldDefinition with field_type=string', async () => {
    const currentCustomFields = await findCustomFieldDefinitionsPaginated(testContext, ADMIN_USER, { first: 50 });
    if (!currentCustomFields.edges.some((cf) => cf.node.id === CF_COMMENT_KEY)) {
      const input: CustomFieldDefinitionAddInput = {
        entity_types: [ENTITY_TYPE_CONTAINER_CASE_INCIDENT],
        field_type: 'string',
        label: 'cf comment',
        name: CF_COMMENT_KEY,
        mandatory: false,
      };
      commentCfField = await customFieldDefinitionAdd(testContext, ADMIN_USER, input);
    }
  });

  it('should use a CustomFieldDefinition on one case incident', async () => {
    const input1: CaseIncidentAddInput = {
      name: `Cf Case Incident One CF - ${Date.now()}`,
      custom_field_values: [
        {
          field_id: CF_COMMENT_KEY,
          field_name: CF_COMMENT_KEY,
          string_value: 'First comment not n i c e',
        },
      ],
      content: 'This is a case incident for custom field',
      confidence: 70,
    };
    caseIncidentOneCustomField = await addCaseIncident(testContext, ADMIN_USER, input1);

    const input2: CaseIncidentAddInput = {
      name: `Cf Case Incident ALL CF - ${Date.now()}`,
      custom_field_values: [
        {
          field_id: CF_SCORE_KEY,
          field_name: CF_SCORE_KEY,
          int_value: 42,
        }, {
          field_id: CF_COMMENT_KEY,
          field_name: CF_COMMENT_KEY,
          string_value: 'What a nice comment !',
        },
      ],
      confidence: 80,
    };
    caseIncidentAllCustomFields = await addCaseIncident(testContext, ADMIN_USER, input2);

    const input3: CaseIncidentAddInput = {
      name: `Cf Case Incident NO CF - ${Date.now()}`,
      confidence: 100,
    };
    caseIncidentNoCustomFields = await addCaseIncident(testContext, ADMIN_USER, input3);
  });

  it('should custom field be visible on schema attribute for Case Incident', async () => {
    const fullShemas = getSchemaAttributes();
    const incidentShemas = fullShemas.find((shema) => shema.type === ENTITY_TYPE_CONTAINER_CASE_INCIDENT);
    console.log('Case incident shema:', incidentShemas);

    const theScore = incidentShemas?.attributes.find((attr) => attr.name === CF_SCORE_KEY);
    expect(theScore).toBeDefined();
    expect(theScore?.type).toBe('numeric');

    const theComment = incidentShemas?.attributes.find((attr) => attr.name === CF_COMMENT_KEY);
    expect(theComment).toBeDefined();
    expect(theComment?.type).toBe('string');
  });

  it('should custom field be visible on filterKeysSchema for Case Incident', async () => {
    const fullFilters = await generateFilterKeysSchema();
    const incidentFilters = fullFilters.find((filter) => filter.entity_type === ENTITY_TYPE_CONTAINER_CASE_INCIDENT);
    console.log('Case incident filter:', incidentFilters);

    const theScore = incidentFilters?.filters_schema.find((filter) => filter.filterDefinition.filterKey === CF_SCORE_KEY);
    console.log('Case incident filter - theScore:', theScore);
    expect(theScore).toBeDefined();
    expect(theScore?.filterDefinition.type).toBe('integer');

    const theComment = incidentFilters?.filters_schema.find((filter) => filter.filterDefinition.filterKey === CF_COMMENT_KEY);
    console.log('Case incident filter - theComment:', theComment);
    expect(theComment).toBeDefined();
    expect(theComment?.filterDefinition.type).toBe('string');
  });

  it('should filter Case Incident list with it', async () => {
    const opts: EntityOptions<BasicStoreEntityCaseIncident> = {
      filters: { mode: FilterMode.And,
        filters: [{ key: ['entity_type'], values: ['Case-Incident'], operator: FilterOperator.Eq, mode: FilterMode.Or }],
        filterGroups: [{ mode: FilterMode.And,
          filters: [
            { key: [CF_SCORE_KEY], values: ['40'], operator: FilterOperator.Gt, mode: FilterMode.Or }, // score is 42 so this should match
            // { key: [CF_COMMENT_KEY], values: ['nice'], operator: FilterOperator.Contains, mode: FilterMode.Or }, // comment is 'What a nice comment !' so this should match
          ], filterGroups: [] }],
      },
    };
    const allCasesFiltered = await findCaseIncidentPaginated(testContext, ADMIN_USER, opts);
    const myIncident = allCasesFiltered.edges.find((c) => c.node.id === caseIncidentAllCustomFields.id);
    console.log('Case incident filter - allCasesFiltered:', myIncident);
  });

  it.skip('should wait', async () => {
    await waitInSec(300);
  });

  it.todo('should cleanup', async () => {
    await deleteElementById(testContext, ADMIN_USER, caseIncidentAllCustomFields.id, ENTITY_TYPE_CONTAINER_CASE_INCIDENT);
    await deleteElementById(testContext, ADMIN_USER, caseIncidentOneCustomField.id, ENTITY_TYPE_CONTAINER_CASE_INCIDENT);
    await deleteElementById(testContext, ADMIN_USER, caseIncidentNoCustomFields.id, ENTITY_TYPE_CONTAINER_CASE_INCIDENT);
    await deleteElementById(testContext, ADMIN_USER, scoreCfField.id, ENTITY_TYPE_CUSTOM_FIELD_DEFINITION);
    await deleteElementById(testContext, ADMIN_USER, commentCfField.id, ENTITY_TYPE_CUSTOM_FIELD_DEFINITION);
  });
});
