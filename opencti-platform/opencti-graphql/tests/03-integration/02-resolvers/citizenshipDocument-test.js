import { expect, it, describe } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQueryHelper';

const LIST_QUERY = gql`
  query citizenshipDocuments(
    $first: Int
    $after: ID
    $orderBy: CitizenshipDocumentsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $search: String
  ) {
    c(
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
          name
          description
        }
      }
    }
  }
`;

const READ_QUERY = gql`
  query citizenshipDocument($id: String!) {
    citizenshipDocument(id: $id) {
      id
      standard_id
      name
      description
      isUser
      organizations {
        edges {
          node {
            id
            standard_id
          }
        }
      }
      toStix
    }
  }
`;

describe('Citizenship Documents resolver standard behavior', () => {
  let citizenshipDocumentInternalId;
  const citizenshipDocumentStixId = 'identity--a7da7a84-73a0-4f1b-b0c0-35ed56418e82';
  it('should citizenship documents created', async () => {
    const CREATE_QUERY = gql`
      mutation CitizenshipDocumentAdd($input: citizenshipDocumentAddInput!) {
        citizenshipDocumentAdd(input: $input) {
          id
          name
          description
        }
      }
    `;
    // Create the citizenship Documents
    const CITIZENSHIP_DOCUMENT_TO_CREATE = {
      input: {
        name: 'CitizenshipDocument',
        stix_id: citizenshipDocumentStixId,
        description: 'Citizenship Documents description',
      },
    };
    const citizenshipDocuments = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: CITIZENSHIP_DOCUMENT_TO_CREATE,
    });
    expect(citizenshipDocuments).not.toBeNull();
    expect(citizenshipDocuments.data.citizenshipDocumentAdd).not.toBeNull();
    expect(citizenshipDocuments.data.citizenshipDocumentAdd.name).toEqual('CitizenshipDocument');
    citizenshipDocumentInternalId = citizenshipDocuments.data.citizenshipDocumentAdd.id;
  });
  it('should citizenship document loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: citizenshipDocumentInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.citizenshipDocument).not.toBeNull();
    expect(queryResult.data.citizenshipDocument.id).toEqual(citizenshipDocumentInternalId);
    expect(queryResult.data.citizenshipDocument.toStix.length).toBeGreaterThan(5);
  });
  it('should citizenship document loaded by stix id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: citizenshipDocumentStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.citizenshipDocument).not.toBeNull();
    expect(queryResult.data.citizenshipDocument.id).toEqual(citizenshipDocumentInternalId);
    expect(queryResult.data.citizenshipDocument.isUser).toBeFalsy();
  });
  it('should list citizenship documents', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.citizenshipDocument.edges.length).toEqual(3);
  });
  it('should update citizenship document', async () => {
    const UPDATE_QUERY = gql`
      mutation CitizenshipDocumentEdit($id: ID!, $input: [EditInput]!) {
        citizenshipDocumentEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            name
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: citizenshipDocumentInternalId, input: { key: 'name', value: ['CitizenshipDocument - test'] } },
    });
    expect(queryResult.data.citizenshipDocumentEdit.fieldPatch.name).toEqual('CitizenshipDocument - test');
  });
  it('should context patch citizenship document', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation CitizenshipDocumentEdit($id: ID!, $input: EditContext) {
        citizenshipDocumentEdit(id: $id) {
          contextPatch(input: $input) {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: citizenshipDocumentInternalId, input: { focusOn: 'description' } },
    });
    expect(queryResult.data.citizenshipDocumentEdit.contextPatch.id).toEqual(citizenshipDocumentInternalId);
  });
  it('should context clean citizenship document', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation CitizenshipDocumentEdit($id: ID!) {
        citizenshipDocumentEdit(id: $id) {
          contextClean {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: citizenshipDocumentInternalId },
    });
    expect(queryResult.data.citizenshipDocumentEdit.contextClean.id).toEqual(citizenshipDocumentInternalId);
  });
  it('should add relation in citizenship document', async () => {
    const RELATION_ADD_QUERY = gql`
      mutation CitizenshipDocumentEdit($id: ID!, $input: StixRefRelationshipAddInput!) {
        citizenshipDocumentEdit(id: $id) {
          relationAdd(input: $input) {
            id
            from {
              ... on CitizenshipDocument {
                objectMarking {
                  id
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
        id: citizenshipDocumentInternalId,
        input: {
          toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
          relationship_type: 'object-marking',
        },
      },
    });
    expect(queryResult.data.citizenshipDocumentEdit.relationAdd.from.objectMarking.length).toEqual(1);
  });
  it('should delete relation in citizenship document', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation citizenshipDocumentEdit($id: ID!, $toId: StixRef!, $relationship_type: String!) {
        citizenshipDocumentEdit(id: $id) {
          relationDelete(toId: $toId, relationship_type: $relationship_type) {
            id
            objectMarking {
              id
            }
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: RELATION_DELETE_QUERY,
      variables: {
        id: citizenshipDocumentInternalId,
        toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
        relationship_type: 'object-marking',
      },
    });
    expect(queryResult.data.citizenshipDocumentEdit.relationDelete.objectMarking.length).toEqual(0);
  });
  it('should citizenship documentsStixId deleted', async () => {
    const DELETE_QUERY = gql`
      mutation citizenshipDocumentDelete($id: ID!) {
        citizenshipDocumentEdit(id: $id) {
          delete
        }
      }
    `;
    // Delete the CitizenshipDocument
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: citizenshipDocumentInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: citizenshipDocumentStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.citizenshipDocument).toBeNull();
  });
});
