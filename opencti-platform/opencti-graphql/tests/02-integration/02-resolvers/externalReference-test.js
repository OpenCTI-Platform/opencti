import { expect, it, describe } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, testContext, queryAsAdmin } from '../../utils/testQuery';
import { elLoadById } from '../../../src/database/engine';
import { computeQueryTaskElements } from '../../../src/manager/taskManager';

const LIST_QUERY = gql`
  query externalReferences(
    $first: Int
    $after: ID
    $orderBy: ExternalReferencesOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $search: String
  ) {
    externalReferences(
      first: $first
      after: $after
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
      search: $search
    ) {
      edges {
        node {
          id
          source_name
          description
          url
          hash
          external_id
        }
      }
    }
  }
`;

const READ_QUERY = gql`
  query externalReference($id: String!) {
    externalReference(id: $id) {
      id
      source_name
      description
      url
      hash
      external_id
      editContext {
        focusOn
        name
      }
    }
  }
`;

describe('ExternalReference resolver standard behavior', () => {
  let externalReferenceInternalId;
  let campaignId;
  const externalReferenceStixId = 'external-reference--e8ff325d-d51b-4e0e-aa1f-9e19ae6c6a65';
  it('should externalReference created', async () => {
    const CREATE_QUERY = gql`
      mutation ExternalReferenceAdd($input: ExternalReferenceAddInput!) {
        externalReferenceAdd(input: $input) {
          id
          source_name
          description
          url
          hash
          external_id
        }
      }
    `;
    // Create the external reference
    const EXTERNAL_REFERENCE_TO_CREATE = {
      input: {
        stix_id: externalReferenceStixId,
        source_name: 'ExternalReferenceForTest',
        description: 'ExternalReference description',
        url: 'https://www.google.com',
      },
    };
    const externalReference = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: EXTERNAL_REFERENCE_TO_CREATE,
    });
    expect(externalReference).not.toBeNull();
    expect(externalReference.data.externalReferenceAdd).not.toBeNull();
    expect(externalReference.data.externalReferenceAdd.source_name).toEqual('ExternalReferenceForTest');
    externalReferenceInternalId = externalReference.data.externalReferenceAdd.id;
  });
  it('should externalReference loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: externalReferenceInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.externalReference).not.toBeNull();
    expect(queryResult.data.externalReference.id).toEqual(externalReferenceInternalId);
  });
  it('should list externalReferences', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.externalReferences.edges.length).toEqual(8);
  });
  it('should list externalReferences with filter', async () => {
    // See https://github.com/OpenCTI-Platform/opencti/issues/7210
    const myFilter = {
      mode: 'and',
      filters: [{ key: ['entity_type'], values: ['External-Reference'], operator: 'eq', mode: 'or' }],
      filterGroups: [{
        mode: 'and',
        filters: [{ key: ['source_name'], values: ['ExternalReferenceForTest'], operator: 'starts_with', mode: 'or' }],
        filterGroups: []
      }]
    };
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10, filters: myFilter } });
    expect(queryResult.data.externalReferences.edges.length).toEqual(1);

    // Verify that the same filter works in background tasks too
    const task = {
      task_filters: JSON.stringify(myFilter),
      type: 'QUERY',
      scope: 'KNOWLEDGE',
      task_expected_number: 1,
    };
    const computedBackgroundTask = await computeQueryTaskElements(testContext, ADMIN_USER, task);

    expect(computedBackgroundTask.elements.length).toBe(1);
  });
  it('should update externalReference', async () => {
    const UPDATE_QUERY = gql`
      mutation ExternalReferenceEdit($id: ID!, $input: [EditInput]!) {
        externalReferenceEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            description
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: {
        id: externalReferenceInternalId,
        input: { key: 'description', value: ['ExternalReference - test'] },
      },
    });
    expect(queryResult.data.externalReferenceEdit.fieldPatch.description).toEqual('ExternalReference - test');
  });
  it('should context patch externalReference', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation ExternalReferenceEdit($id: ID!, $input: EditContext) {
        externalReferenceEdit(id: $id) {
          contextPatch(input: $input) {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: externalReferenceInternalId, input: { focusOn: 'description' } },
    });
    expect(queryResult.data.externalReferenceEdit.contextPatch.id).toEqual(externalReferenceInternalId);
  });
  it('should externalReference editContext to be accurate', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: externalReferenceInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.externalReference).not.toBeNull();
    expect(queryResult.data.externalReference.id).toEqual(externalReferenceInternalId);
    expect(queryResult.data.externalReference.editContext[0].focusOn).toEqual('description');
  });
  it('should context clean externalReference', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation ExternalReferenceEdit($id: ID!) {
        externalReferenceEdit(id: $id) {
          contextClean {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: externalReferenceInternalId },
    });
    expect(queryResult.data.externalReferenceEdit.contextClean.id).toEqual(externalReferenceInternalId);
  });
  it('should add relation in externalReference', async () => {
    const campaign = await elLoadById(testContext, ADMIN_USER, 'campaign--92d46985-17a6-4610-8be8-cc70c82ed214');
    campaignId = campaign.internal_id;
    const RELATION_ADD_QUERY = gql`
      mutation ExternalReferenceEdit($id: ID!, $input: StixRefRelationshipAddInput!) {
        externalReferenceEdit(id: $id) {
          relationAdd(input: $input) {
            id
            from {
              ... on StixDomainObject {
                externalReferences {
                  edges {
                    node {
                      id
                      standard_id
                    }
                  }
                }
              }
            }
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: RELATION_ADD_QUERY,
      variables: {
        id: externalReferenceInternalId,
        input: {
          fromId: campaignId,
          relationship_type: 'external-reference',
        },
      },
    });
    expect(queryResult.data.externalReferenceEdit.relationAdd.from.externalReferences.edges.length).toEqual(1);
  });
  it('should delete relation in externalReference', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation ExternalReferenceEdit($id: ID!, $fromId: StixRef!, $relationship_type: String!) {
        externalReferenceEdit(id: $id) {
          relationDelete(fromId: $fromId, relationship_type: $relationship_type) {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: RELATION_DELETE_QUERY,
      variables: {
        id: externalReferenceInternalId,
        fromId: campaignId,
        relationship_type: 'external-reference',
      },
    });
    expect(queryResult.data.externalReferenceEdit.relationDelete.id).toEqual(externalReferenceInternalId);
  });
  it('should externalReference deleted', async () => {
    const DELETE_QUERY = gql`
      mutation externalReferenceDelete($id: ID!) {
        externalReferenceEdit(id: $id) {
          delete
        }
      }
    `;
    // Delete the externalReference
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: externalReferenceInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: externalReferenceStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.externalReference).toBeNull();
  });
});
