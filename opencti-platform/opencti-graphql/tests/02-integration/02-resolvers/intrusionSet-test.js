import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';

const READ_QUERY = gql`
  query intrusionSet($id: String!) {
    intrusionSet(id: $id) {
      id
      name
      description
    }
  }
`;

describe('Intrusion set resolver standard behavior', () => {
  let intrusionSetInternalId;
  const intrusionSetStixId = 'intrusion-set--952ec932-a8c8-4050-9662-f0771ed7c477';
  it('should intrusion set created', async () => {
    const CREATE_QUERY = gql`
      mutation IntrusionSetAdd($input: IntrusionSetAddInput) {
        intrusionSetAdd(input: $input) {
          id
          name
          description
        }
      }
    `;
    // Create the intrusion set
    const INTRUSION_SET_TO_CREATE = {
      input: {
        name: 'Intrusion set',
        stix_id_key: intrusionSetStixId,
        description: 'Intrusion set description'
      }
    };
    const intrusionSet = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: INTRUSION_SET_TO_CREATE
    });
    expect(intrusionSet).not.toBeNull();
    expect(intrusionSet.data.intrusionSetAdd).not.toBeNull();
    expect(intrusionSet.data.intrusionSetAdd.name).toEqual('Intrusion set');
    intrusionSetInternalId = intrusionSet.data.intrusionSetAdd.id;
  });
  it('should intrusion set loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: intrusionSetInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.intrusionSet).not.toBeNull();
    expect(queryResult.data.intrusionSet.id).toEqual(intrusionSetInternalId);
  });
  it('should intrusion set loaded by stix id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: intrusionSetStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.intrusionSet).not.toBeNull();
    expect(queryResult.data.intrusionSet.id).toEqual(intrusionSetInternalId);
    // Delete the intrusion set
  });
  it('should intrusion set deleted', async () => {
    const DELETE_QUERY = gql`
      mutation intrusionSetDelete($id: ID!) {
        intrusionSetEdit(id: $id) {
          delete
        }
      }
    `;
    // Delete the intrusion set
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: intrusionSetInternalId }
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: intrusionSetStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.intrusionSet).toBeNull();
  });
});
