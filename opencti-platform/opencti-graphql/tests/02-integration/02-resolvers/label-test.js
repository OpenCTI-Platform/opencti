import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';

const LIST_QUERY = gql`
  query labels($first: Int, $after: ID, $orderBy: LabelsOrdering, $orderMode: OrderingMode, $search: String) {
    labels(first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode, search: $search) {
      edges {
        node {
          id
          value
        }
      }
    }
  }
`;

const READ_QUERY = gql`
  query label($id: String!) {
    label(id: $id) {
      id
      value
    }
  }
`;

describe('Label resolver standard behavior', () => {
  let labelInternalId;
  it('should label created', async () => {
    const CREATE_QUERY = gql`
      mutation LabelAdd($input: LabelAddInput) {
        labelAdd(input: $input) {
          id
          value
          color
        }
      }
    `;
    // Create the label
    const LABEL_TO_CREATE = {
      input: {
        value: 'State-Sponsored',
        color: '#000000',
      },
    };
    const label = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: LABEL_TO_CREATE,
    });
    expect(label).not.toBeNull();
    expect(label.data.labelAdd).not.toBeNull();
    expect(label.data.labelAdd.value).toEqual('state-sponsored');
    labelInternalId = label.data.labelAdd.id;
  });
  it('should label loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: labelInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.label).not.toBeNull();
    expect(queryResult.data.label.id).toEqual(labelInternalId);
  });
  it('should list labels', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 30 } });
    expect(queryResult.data.labels.edges.length).toEqual(14);
  });
  it('should update label', async () => {
    const UPDATE_QUERY = gql`
      mutation LabelEdit($id: ID!, $input: [EditInput]!) {
        labelEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            value
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: labelInternalId, input: { key: 'value', value: ['State-Sponsored2'] } },
    });
    expect(queryResult.data.labelEdit.fieldPatch.value).toEqual('state-sponsored2');
  });
  it('should context patch label', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation LabelEdit($id: ID!, $input: EditContext) {
        labelEdit(id: $id) {
          contextPatch(input: $input) {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: labelInternalId, input: { focusOn: 'value' } },
    });
    expect(queryResult.data.labelEdit.contextPatch.id).toEqual(labelInternalId);
  });
  it('should context clean label', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation LabelEdit($id: ID!) {
        labelEdit(id: $id) {
          contextClean {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: labelInternalId },
    });
    expect(queryResult.data.labelEdit.contextClean.id).toEqual(labelInternalId);
  });
  it('should label deleted', async () => {
    const DELETE_QUERY = gql`
      mutation labelDelete($id: ID!) {
        labelEdit(id: $id) {
          delete
        }
      }
    `;
    // Delete the label
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: labelInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: labelInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.label).toBeNull();
  });
});
