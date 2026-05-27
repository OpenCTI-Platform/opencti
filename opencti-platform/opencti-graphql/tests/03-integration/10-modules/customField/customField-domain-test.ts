import { describe, it, expect } from 'vitest';
import { customFieldDefinitionAdd, findCustomFieldDefinitionsPaginated } from '../../../../src/modules/customField/custom-field-domain';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import type { CaseIncidentAddInput, CustomFieldDefinitionAddInput } from '../../../../src/generated/graphql';
import { type BasicStoreEntityCaseIncident, ENTITY_TYPE_CONTAINER_CASE_INCIDENT } from '../../../../src/modules/case/case-incident/case-incident-types';
import { type BasicStoreEntityCustomFieldDefinition, ENTITY_TYPE_CUSTOM_FIELD_DEFINITION } from '../../../../src/modules/customField/custom-field-types';
import { addCaseIncident } from '../../../../src/modules/case/case-incident/case-incident-domain';
import { waitInSec } from '../../../../src/database/utils';
import { getSchemaAttributes } from '../../../../src/domain/attribute';
import { deleteElementById } from '../../../../src/database/middleware';

describe('CustomFieldDefinition — domain coverage', () => {
  let scoreCfField: BasicStoreEntityCustomFieldDefinition;
  let commentCfField: BasicStoreEntityCustomFieldDefinition;
  let caseIncident: BasicStoreEntityCaseIncident;

  const CF_SCORE_KEY = 'x_opencti_cf_score';
  const CF_COMMENT_KEY = 'x_opencti_cf_comment';

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
    const input: CaseIncidentAddInput = {
      name: `Cf Case Incident - ${Date.now()}`,
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
    };
    caseIncident = await addCaseIncident(testContext, ADMIN_USER, input);
  });

  it('should filters on custom field be visible for Case Incident', async () => {
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

  it('should wait', async () => {
    await waitInSec(300);
  });

  it.todo('should cleanup', async () => {
    await deleteElementById(testContext, ADMIN_USER, caseIncident.id, ENTITY_TYPE_CONTAINER_CASE_INCIDENT);
    await deleteElementById(testContext, ADMIN_USER, scoreCfField.id, ENTITY_TYPE_CUSTOM_FIELD_DEFINITION);
    await deleteElementById(testContext, ADMIN_USER, commentCfField.id, ENTITY_TYPE_CUSTOM_FIELD_DEFINITION);
  });
});
