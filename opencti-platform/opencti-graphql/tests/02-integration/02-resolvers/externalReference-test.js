import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';

const LIST_QUERY = gql`
  query externalReferences(
    $first: Int
    $after: ID
    $orderBy: ExternalReferencesOrdering
    $orderMode: OrderingMode
    $filters: [ExternalReferencesFiltering]
    $filterMode: FilterMode
    $search: String
  ) {
    externalReferences(
      first: $first
      after: $after
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
      filterMode: $filterMode
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
    }
  }
`;

describe('ExternalReference resolver standard behavior', () => {
  let externalReferenceInternalId;
  let externalReferenceStixDomainEntityRelationId;
  const externalReferenceStixId = 'external-reference--e8ff325d-d51b-4e0e-aa1f-9e19ae6c6a65';
  it('should externalReference created', async () => {
    const CREATE_QUERY = gql`
      mutation ExternalReferenceAdd($input: ExternalReferenceAddInput) {
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
        stix_id_key: externalReferenceStixId,
        source_name: 'ExternalReference',
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
    expect(externalReference.data.externalReferenceAdd.source_name).toEqual('ExternalReference');
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
  it('should update externalReference', async () => {
    const UPDATE_QUERY = gql`
      mutation ExternalReferenceEdit($id: ID!, $input: EditInput!) {
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
    const RELATION_ADD_QUERY = gql`
      mutation ExternalReferenceEdit($id: ID!, $input: RelationAddInput!) {
        externalReferenceEdit(id: $id) {
          relationAdd(input: $input) {
            id
            from {
              ... on StixDomainEntity {
                externalReferences {
                  edges {
                    node {
                      id
                    }
                    relation {
                      id
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
        id: 'fab6fa99-b07f-4278-86b4-b674edf60877',
        input: {
          fromRole: 'so',
          toRole: 'external_reference',
          toId: externalReferenceInternalId,
          through: 'external_references',
        },
      },
    });
    expect(queryResult.data.externalReferenceEdit.relationAdd.from.externalReferences.edges.length).toEqual(1);
    externalReferenceStixDomainEntityRelationId =
      queryResult.data.externalReferenceEdit.relationAdd.from.externalReferences.edges[0].relation.id;
  });
  it('should delete relation in externalReference', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation ExternalReferenceEdit($id: ID!, $relationId: ID!) {
        externalReferenceEdit(id: $id) {
          relationDelete(relationId: $relationId) {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: RELATION_DELETE_QUERY,
      variables: {
        id: externalReferenceInternalId,
        relationId: externalReferenceStixDomainEntityRelationId,
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
