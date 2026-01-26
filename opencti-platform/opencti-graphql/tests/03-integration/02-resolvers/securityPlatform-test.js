import { expect, it, describe } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';

const LIST_QUERY = gql`
  query securityPlatforms(
    $first: Int
    $after: ID
    $orderBy: SecurityPlatformOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $search: String
  ) {
    securityPlatforms(
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
          identity_class
          standard_id
          description
          name
          security_platform_type
        }
      }
    }
  }
`;

const READ_QUERY = gql`
  query securityPlatform($id: String!) {
    securityPlatform(id: $id) {
      id
      standard_id
      name
      description
      security_platform_type
    }
  }
`;

const UPDATE_QUERY = gql`
  mutation securityPlatformEdit($id: ID!, $input: [EditInput]!){
    securityPlatformFieldPatch(id: $id, input: $input) {
      id
      name
      description
      security_platform_type
    }
  }
`;

const DELETE_QUERY = gql`
  mutation securityPlatformDelete($id: ID!){
    securityPlatformDelete(id: $id)
  }
`;

describe('SecurityPlatform resolver tests', () => {
  let securityPlatformInternalId;
  it('should security platform created', async () => {
    const CREATE_QUERY = gql`
      mutation SecurityPlatformAdd($input: SecurityPlatformAddInput!) {
        securityPlatformAdd(input: $input) {
          id
          name
          description
          security_platform_type
        }
      }
    `;

    // Create the security platform
    const SECURITY_PLATFORM_TO_CREATE = {
      input: {
        name: 'Security platform test',
        description: 'Security platform test description',
      }
    };
    const securityPlatform = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: SECURITY_PLATFORM_TO_CREATE,
    });
    expect(securityPlatform).not.toBeNull();
    expect(securityPlatform.data.securityPlatformAdd).not.toBeNull();
    expect(securityPlatform.data.securityPlatformAdd.name).toEqual('Security platform test');
    expect(securityPlatform.data.securityPlatformAdd.description).toEqual('Security platform test description');
    securityPlatformInternalId = securityPlatform.data.securityPlatformAdd.id;
  });
  it('should security platform loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: securityPlatformInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.securityPlatform).not.toBeNull();
    expect(queryResult.data.securityPlatform.id).toEqual(securityPlatformInternalId);
  });
  it('should list security platforms', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.securityPlatforms.edges.length).toEqual(1);
  });
  it('should update security platform', async () => {
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: securityPlatformInternalId, input: { key: 'description', value: ['Security platform - description'] } },
    });
    expect(queryResult.data.securityPlatformFieldPatch.description).toEqual('Security platform - description');
  });
  it.skip('should add relation in security platform', async () => {
    const RELATION_ADD_QUERY = gql`
      mutation SecurityPlatformEdit($id: ID!, $input: StixRefRelationshipAddInput!) {
        securityPlatformRelationAdd(id: $id, input: $input) {
          id
          from {
            ... on SecurityPlatform {
              objectMarking {
                id
              }
            }
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: RELATION_ADD_QUERY,
      variables: {
        id: securityPlatformInternalId,
        input: {
          toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
          relationship_type: 'object-marking',
        },
      },
    });
    expect(queryResult.data.securityPlatformRelationAdd.from.objectMarking.length).toEqual(1);
  });
  it.skip('should delete relation in security platform', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation OrganizationDelete($id: ID!, $toId: StixRef!, $relationship_type: String!) {
        securityPlatformRelationDelete(id: $id, toId: $toId, relationship_type: $relationship_type) {
          id
          objectMarking {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: RELATION_DELETE_QUERY,
      variables: {
        id: securityPlatformInternalId,
        toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
        relationship_type: 'object-marking',
      },
    });
    expect(queryResult.data.securityPlatformRelationDelete.objectMarking.length).toEqual(0);
  });
  it('should security platform deleted', async () => {
    // Delete the organization
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: securityPlatformInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: securityPlatformInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.securityPlatform).toBeNull();
  });
});
