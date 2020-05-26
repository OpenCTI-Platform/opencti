import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';

const LIST_QUERY = gql`
  query attributes(
    $first: Int
    $after: ID
    $orderBy: AttributesOrdering
    $orderMode: OrderingMode
    $type: String
    $search: String
  ) {
    attributes(first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode, type: $type, search: $search) {
      edges {
        node {
          id
          type
          value
        }
      }
    }
  }
`;

const READ_QUERY = gql`
  query attribute($id: String!) {
    attribute(id: $id) {
      id
      type
      value
    }
  }
`;

describe('Attribute resolver standard behavior', () => {
  let attributeInternalId;
  it('should attribute created', async () => {
    const CREATE_QUERY = gql`
      mutation AttributeAdd($input: AttributeAddInput) {
        attributeAdd(input: $input) {
          id
          type
          value
        }
      }
    `;
    // Create the country
    const ATTRIBUTE_TO_CREATE = {
      input: {
        type: 'role_played',
        value: 'Test',
      },
    };
    const attribute = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: ATTRIBUTE_TO_CREATE,
    });
    expect(attribute).not.toBeNull();
    expect(attribute.data.attributeAdd).not.toBeNull();
    expect(attribute.data.attributeAdd.value).toEqual('Test');
    attributeInternalId = attribute.data.attributeAdd.id;
  });
  it('should attribute loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: attributeInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.attribute).not.toBeNull();
    expect(queryResult.data.attribute.id).toEqual(attributeInternalId);
  });
  it('should update attribute', async () => {
    const UPDATE_QUERY = gql`
      mutation AttributeEdit($id: ID!, $input: AttributeEditInput!) {
        attributeEdit(id: $id) {
          update(input: $input) {
            id
            type
            value
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: attributeInternalId, input: { type: 'role_played', value: 'Test', newValue: 'Test2' } },
    });
    expect(queryResult.data.attributeEdit.update.value).toEqual('Test2');
    attributeInternalId = queryResult.data.attributeEdit.update.id;
  });
  it('should list attributes', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { type: 'role_played' } });
    expect(queryResult.data.attributes.edges.length).toEqual(4);
  });
  it('should attribute deleted', async () => {
    const DELETE_QUERY = gql`
      mutation attributeDelete($id: ID!) {
        attributeEdit(id: $id) {
          delete
        }
      }
    `;
    // Delete the country
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: attributeInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: attributeInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.attribute).toBeNull();
  });
});
