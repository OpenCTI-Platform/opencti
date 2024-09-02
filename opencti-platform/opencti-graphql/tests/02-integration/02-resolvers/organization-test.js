import { expect, it, describe } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, testContext, queryAsAdmin } from '../../utils/testQuery';
import { elLoadById } from '../../../src/database/engine';

const LIST_QUERY = gql`
  query organizations(
    $first: Int
    $after: ID
    $orderBy: OrganizationsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $search: String
  ) {
    organizations(
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
  query organization($id: String!) {
    organization(id: $id) {
      id
      standard_id
      name
      description
      sectors {
        edges {
          node {
            id
            standard_id
          }
        }
      }
      subOrganizations {
        edges {
          node {
            id
            standard_id
            name
          }
        }
      }
      toStix
    }
  }
`;

describe('Organization resolver standard behavior', () => {
  let organizationInternalId;
  const organizationStixId = 'identity--43008345-56bd-4175-adad-312bef2ff6a1';
  it('should organization created', async () => {
    const CREATE_QUERY = gql`
      mutation OrganizationAdd($input: OrganizationAddInput!) {
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
        stix_id: organizationStixId,
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
    const organization = await elLoadById(testContext, ADMIN_USER, 'identity--c017f212-546b-4f21-999d-97d3dc558f7b');
    const queryResult = await queryAsAdmin({
      query: READ_QUERY,
      variables: { id: organization.internal_id },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.organization).not.toBeNull();
    expect(queryResult.data.organization.standard_id).toEqual('identity--732421a0-8471-52de-8d9f-18c8b260813c');
    expect(queryResult.data.organization.sectors.edges.length).toEqual(1);
    expect(queryResult.data.organization.sectors.edges[0].node.standard_id).toEqual(
      'identity--6e24d2a6-6ce1-5fbb-b3c6-e37f1dc381ff'
    );
  });
  it('should organization sub-organizations be accurate', async () => {
    const organization = await elLoadById(testContext, ADMIN_USER, 'identity--7b82b010-b1c0-4dae-981f-7756374a17df');
    const queryResult = await queryAsAdmin({
      query: READ_QUERY,
      variables: { id: organization.internal_id },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.organization).not.toBeNull();
    expect(queryResult.data.organization.subOrganizations.edges.length).toEqual(1);
    expect(queryResult.data.organization.subOrganizations.edges[0].node.standard_id).toEqual(
      'identity--8c641a55-16b5-503d-9cc3-bf68ef0c40cc'
    );
  });
  it('should list organizations', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.organizations.edges.length).toEqual(9);
  });
  it('should update organization', async () => {
    const UPDATE_QUERY = gql`
      mutation OrganizationEdit($id: ID!, $input: [EditInput]!) {
        organizationFieldPatch(id: $id, input: $input) {
          id
          name
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: organizationInternalId, input: { key: 'name', value: ['Organization - test'] } },
    });
    expect(queryResult.data.organizationFieldPatch.name).toEqual('Organization - test');
  });
  it('should context patch organization', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation OrganizationEdit($id: ID!, $input: EditContext!) {
        organizationContextPatch(id: $id, input: $input) {
          id
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: organizationInternalId, input: { focusOn: 'description' } },
    });
    expect(queryResult.data.organizationContextPatch.id).toEqual(organizationInternalId);
  });
  it('should context clean organization', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation OrganizationEdit($id: ID!) {
        organizationContextClean(id: $id) {
          id
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: organizationInternalId },
    });
    expect(queryResult.data.organizationContextClean.id).toEqual(organizationInternalId);
  });
  it('should add relation in organization', async () => {
    const RELATION_ADD_QUERY = gql`
      mutation OrganizationEdit($id: ID!, $input: StixRefRelationshipAddInput!) {
        organizationRelationAdd(id: $id, input: $input) {
          id
          from {
            ... on Organization {
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
        id: organizationInternalId,
        input: {
          toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
          relationship_type: 'object-marking',
        },
      },
    });
    expect(queryResult.data.organizationRelationAdd.from.objectMarking.length).toEqual(1);
  });
  it('should delete relation in organization', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation OrganizationEdit($id: ID!, $toId: StixRef!, $relationship_type: String!) {
        organizationRelationDelete(id: $id, toId: $toId, relationship_type: $relationship_type) {
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
        id: organizationInternalId,
        toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
        relationship_type: 'object-marking',
      },
    });
    expect(queryResult.data.organizationRelationDelete.objectMarking.length).toEqual(0);
  });
  it('should organization deleted', async () => {
    const DELETE_QUERY = gql`
      mutation organizationDelete($id: ID!) {
        organizationDelete(id: $id)
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
