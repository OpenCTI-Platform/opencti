import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';

const LIST_QUERY = gql`
  query tags($first: Int, $after: ID, $orderBy: TagsOrdering, $orderMode: OrderingMode, $search: String) {
    tags(first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode, search: $search) {
      edges {
        node {
          id
          tag_type
          value
        }
      }
    }
  }
`;

const READ_QUERY = gql`
  query tag($id: String!) {
    tag(id: $id) {
      id
      tag_type
      value
    }
  }
`;

describe('Tag resolver standard behavior', () => {
  let tagInternalId;
  it('should tag created', async () => {
    const CREATE_QUERY = gql`
      mutation TagAdd($input: TagAddInput) {
        tagAdd(input: $input) {
          id
          tag_type
          value
          color
        }
      }
    `;
    // Create the tag
    const TAG_TO_CREATE = {
      input: {
        tag_type: 'Threat-Type',
        value: 'State-Sponsored',
        color: '#000000',
      },
    };
    const tag = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: TAG_TO_CREATE,
    });
    expect(tag).not.toBeNull();
    expect(tag.data.tagAdd).not.toBeNull();
    expect(tag.data.tagAdd.tag_type).toEqual('Threat-Type');
    tagInternalId = tag.data.tagAdd.id;
  });
  it('should tag loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: tagInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.tag).not.toBeNull();
    expect(queryResult.data.tag.id).toEqual(tagInternalId);
  });
  it('should list tags', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.tags.edges.length).toEqual(4);
  });
  it('should update tag', async () => {
    const UPDATE_QUERY = gql`
      mutation TagEdit($id: ID!, $input: EditInput!) {
        tagEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            value
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: tagInternalId, input: { key: 'value', value: ['State-Sponsored2'] } },
    });
    expect(queryResult.data.tagEdit.fieldPatch.value).toEqual('State-Sponsored2');
  });
  it('should context patch tag', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation TagEdit($id: ID!, $input: EditContext) {
        tagEdit(id: $id) {
          contextPatch(input: $input) {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: tagInternalId, input: { focusOn: 'value' } },
    });
    expect(queryResult.data.tagEdit.contextPatch.id).toEqual(tagInternalId);
  });
  it('should context clean tag', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation TagEdit($id: ID!) {
        tagEdit(id: $id) {
          contextClean {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: tagInternalId },
    });
    expect(queryResult.data.tagEdit.contextClean.id).toEqual(tagInternalId);
  });
  it('should tag deleted', async () => {
    const DELETE_QUERY = gql`
      mutation tagDelete($id: ID!) {
        tagEdit(id: $id) {
          delete
        }
      }
    `;
    // Delete the tag
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: tagInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: tagInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.tag).toBeNull();
  });
});
