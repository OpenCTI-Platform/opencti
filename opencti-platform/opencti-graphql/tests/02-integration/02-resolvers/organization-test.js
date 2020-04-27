import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';

const LIST_QUERY = gql`
  query organizations(
    $first: Int
    $after: ID
    $orderBy: OrganizationsOrdering
    $orderMode: OrderingMode
    $filters: [OrganizationsFiltering]
    $filterMode: FilterMode
    $search: String
  ) {
    organizations(
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
          name
          description
        }
      }
    }
  }
`;

const READ_QUERY = gql`
  query organization($id: String!) {
    organization(id: $id) {
      id
      name
      description
      sectors {
        edges {
          node {
            id
          }
        }
      }
      toStix
    }
  }
`;

describe('Organization resolver standard behavior', () => {
  let organizationInternalId;
  let organizationMarkingDefinitionRelationId;
  const organizationStixId = 'identity--43008345-56bd-4175-adad-312bef2ff6a1';
  it('should organization created', async () => {
    const CREATE_QUERY = gql`
      mutation OrganizationAdd($input: OrganizationAddInput) {
        organizationAdd(input: $input) {
          id
          name
          description
        }
      }
    `;
    // Create the organization
    const ORGANIZATION_TO_CREATE = {
      input: {
        name: 'Organization',
        stix_id_key: organizationStixId,
        description: 'Organization description',
      },
    };
    const organization = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: ORGANIZATION_TO_CREATE,
    });
    expect(organization).not.toBeNull();
    expect(organization.data.organizationAdd).not.toBeNull();
    expect(organization.data.organizationAdd.name).toEqual('Organization');
    organizationInternalId = organization.data.organizationAdd.id;
  });
  it('should organization loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: organizationInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.organization).not.toBeNull();
    expect(queryResult.data.organization.id).toEqual(organizationInternalId);
    expect(queryResult.data.organization.toStix.length).toBeGreaterThan(5);
  });
  it('should organization loaded by stix id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: organizationStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.organization).not.toBeNull();
    expect(queryResult.data.organization.id).toEqual(organizationInternalId);
  });
  it('should organization sectors be accurate', async () => {
    const queryResult = await queryAsAdmin({
      query: READ_QUERY,
      variables: { id: '9ca2ff43-b765-4f13-a213-10664a2ae8fc' },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.organization).not.toBeNull();
    expect(queryResult.data.organization.id).toEqual('9ca2ff43-b765-4f13-a213-10664a2ae8fc');
    expect(queryResult.data.organization.sectors.edges.length).toEqual(1);
    expect(queryResult.data.organization.sectors.edges[0].node.id).toEqual('9dcde1a4-88ef-4f50-ad74-23d865b438e6');
  });
  it('should list organizations', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.organizations.edges.length).toEqual(6);
  });
  it('should update organization', async () => {
    const UPDATE_QUERY = gql`
      mutation OrganizationEdit($id: ID!, $input: EditInput!) {
        organizationEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            name
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: organizationInternalId, input: { key: 'name', value: ['Organization - test'] } },
    });
    expect(queryResult.data.organizationEdit.fieldPatch.name).toEqual('Organization - test');
  });
  it('should context patch organization', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation OrganizationEdit($id: ID!, $input: EditContext) {
        organizationEdit(id: $id) {
          contextPatch(input: $input) {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: organizationInternalId, input: { focusOn: 'description' } },
    });
    expect(queryResult.data.organizationEdit.contextPatch.id).toEqual(organizationInternalId);
  });
  it('should context clean organization', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation OrganizationEdit($id: ID!) {
        organizationEdit(id: $id) {
          contextClean {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: organizationInternalId },
    });
    expect(queryResult.data.organizationEdit.contextClean.id).toEqual(organizationInternalId);
  });
  it('should add relation in organization', async () => {
    const RELATION_ADD_QUERY = gql`
      mutation OrganizationEdit($id: ID!, $input: RelationAddInput!) {
        organizationEdit(id: $id) {
          relationAdd(input: $input) {
            id
            from {
              ... on Organization {
                markingDefinitions {
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
        id: organizationInternalId,
        input: {
          fromRole: 'so',
          toRole: 'marking',
          toId: '43f586bc-bcbc-43d1-ab46-43e5ab1a2c46',
          through: 'object_marking_refs',
        },
      },
    });
    expect(queryResult.data.organizationEdit.relationAdd.from.markingDefinitions.edges.length).toEqual(1);
    organizationMarkingDefinitionRelationId =
      queryResult.data.organizationEdit.relationAdd.from.markingDefinitions.edges[0].relation.id;
  });
  it('should delete relation in organization', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation OrganizationEdit($id: ID!, $relationId: ID!) {
        organizationEdit(id: $id) {
          relationDelete(relationId: $relationId) {
            id
            markingDefinitions {
              edges {
                node {
                  id
                }
              }
            }
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: RELATION_DELETE_QUERY,
      variables: {
        id: organizationInternalId,
        relationId: organizationMarkingDefinitionRelationId,
      },
    });
    expect(queryResult.data.organizationEdit.relationDelete.markingDefinitions.edges.length).toEqual(0);
  });
  it('should organization deleted', async () => {
    const DELETE_QUERY = gql`
      mutation organizationDelete($id: ID!) {
        organizationEdit(id: $id) {
          delete
        }
      }
    `;
    // Delete the organization
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: organizationInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: organizationStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.organization).toBeNull();
  });
});
