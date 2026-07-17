import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQueryHelper';

const CUSTOM_FIELD_ADD_QUERY = gql`
  mutation CustomFieldDefinitionAddForCaseIncidentTest($input: CustomFieldDefinitionAddInput!) {
    customFieldDefinitionAdd(input: $input) {
      id
      name
      label
    }
  }
`;

const CUSTOM_FIELD_ADD_ENTITY_TYPE_QUERY = gql`
  mutation CustomFieldDefinitionAddEntityTypeForCaseIncidentTest($id: ID!, $entityType: String!, $mandatory: Boolean!) {
    customFieldDefinitionAddEntityType(id: $id, entityType: $entityType, mandatory: $mandatory) {
      id
    }
  }
`;

const CUSTOM_FIELD_DELETE_QUERY = gql`
  mutation CustomFieldDefinitionDeleteForCaseIncidentTest($id: ID!) {
    customFieldDefinitionDelete(id: $id)
  }
`;

const CASE_INCIDENT_ADD_QUERY = gql`
  mutation CaseIncidentAddForCustomFieldTest($input: CaseIncidentAddInput!) {
    caseIncidentAdd(input: $input) {
      id
      standard_id
      name
      customFieldValues {
        field_id
        field_name
        int_value
      }
    }
  }
`;

const CASE_INCIDENT_READ_QUERY = gql`
  query CaseIncidentReadForCustomFieldTest($id: String!) {
    caseIncident(id: $id) {
      id
      name
      customFieldValues {
        field_id
        field_name
        int_value
      }
    }
  }
`;

const CASE_INCIDENT_FIELD_PATCH_QUERY = gql`
  mutation CaseIncidentFieldPatchForCustomFieldTest($id: ID!, $input: [EditInput]!) {
    stixDomainObjectEdit(id: $id) {
      fieldPatch(input: $input) {
        id
        ... on CaseIncident {
          customFieldValues {
            field_id
            field_name
            int_value
          }
        }
      }
    }
  }
`;

const CASE_INCIDENT_DELETE_QUERY = gql`
  mutation CaseIncidentDeleteForCustomFieldTest($id: ID!) {
    caseIncidentDelete(id: $id)
  }
`;

describe('Custom fields wired on Case-Incident', () => {
  let customFieldId: string;
  let customFieldName: string;
  let caseIncidentId: string;

  it('should create an integer custom field definition attached to Case-Incident', async () => {
    const addResult = await queryAsAdmin({
      query: CUSTOM_FIELD_ADD_QUERY,
      variables: {
        input: {
          name: 'x_opencti_cf_test_case_incident_score',
          label: 'Test Case Incident Score',
          field_type: 'integer',
          min_value: 0,
          max_value: 100,
        },
      },
    });
    expect(addResult.errors).toBeUndefined();
    expect(addResult.data).not.toBeNull();
    customFieldId = addResult.data?.customFieldDefinitionAdd.id;
    customFieldName = addResult.data?.customFieldDefinitionAdd.name;
    expect(customFieldId).toBeDefined();

    const attachResult = await queryAsAdmin({
      query: CUSTOM_FIELD_ADD_ENTITY_TYPE_QUERY,
      variables: { id: customFieldId, entityType: 'Case-Incident', mandatory: false },
    });
    expect(attachResult.errors).toBeUndefined();
  });

  it('should set the custom field value when creating a Case-Incident', async () => {
    const createResult = await queryAsAdmin({
      query: CASE_INCIDENT_ADD_QUERY,
      variables: {
        input: {
          name: 'Case Incident with custom field',
          customFieldValues: [
            { field_id: customFieldId, field_name: customFieldName, int_value: 42 },
          ],
        },
      },
    });
    expect(createResult.errors).toBeUndefined();
    expect(createResult.data).not.toBeNull();
    caseIncidentId = createResult.data?.caseIncidentAdd.id;
    const values = createResult.data?.caseIncidentAdd.customFieldValues;
    expect(values).toHaveLength(1);
    expect(values[0].int_value).toEqual(42);
  });

  it('should read back the custom field value on the Case-Incident', async () => {
    const readResult = await queryAsAdmin({ query: CASE_INCIDENT_READ_QUERY, variables: { id: caseIncidentId } });
    expect(readResult.errors).toBeUndefined();
    expect(readResult.data).not.toBeNull();
    const values = readResult.data?.caseIncident.customFieldValues;
    expect(values).toHaveLength(1);
    expect(values[0].field_name).toEqual(customFieldName);
    expect(values[0].int_value).toEqual(42);
  });

  it('should update the custom field value through the generic fieldPatch mutation', async () => {
    const patchResult = await queryAsAdmin({
      query: CASE_INCIDENT_FIELD_PATCH_QUERY,
      variables: {
        id: caseIncidentId,
        input: { key: 'custom_field_values', value: [{ field_id: customFieldId, field_name: customFieldName, int_value: 55 }] },
      },
    });
    expect(patchResult.errors).toBeUndefined();
    expect(patchResult.data).not.toBeNull();
    const values = patchResult.data?.stixDomainObjectEdit.fieldPatch.customFieldValues;
    expect(values).toHaveLength(1);
    expect(values[0].int_value).toEqual(55);
  });

  it('should reject an out-of-bounds custom field value on edit', async () => {
    const patchResult = await queryAsAdmin({
      query: CASE_INCIDENT_FIELD_PATCH_QUERY,
      variables: {
        id: caseIncidentId,
        input: { key: 'custom_field_values', value: [{ field_id: customFieldId, field_name: customFieldName, int_value: 999 }] },
      },
    });
    expect(patchResult.errors).toBeDefined();
  });

  it('should cleanup the Case-Incident and the custom field definition', async () => {
    const deleteCaseResult = await queryAsAdmin({ query: CASE_INCIDENT_DELETE_QUERY, variables: { id: caseIncidentId } });
    expect(deleteCaseResult.errors).toBeUndefined();
    const deleteCustomFieldResult = await queryAsAdmin({ query: CUSTOM_FIELD_DELETE_QUERY, variables: { id: customFieldId } });
    expect(deleteCustomFieldResult.errors).toBeUndefined();
  });
});
