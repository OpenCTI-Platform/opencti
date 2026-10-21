import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { USER_EDITOR } from '../../utils/testQuery';
import { queryAsAdminWithSuccess, queryAsUserWithSuccess } from '../../utils/testQueryHelper';
import { MARKING_TLP_RED } from '../../../src/schema/identifier';

const CREATE_ORGANIZATION_QUERY = gql`
  mutation OrganizationAdd($input: OrganizationAddInput!) {
    organizationAdd(input: $input) {
      id
    }
  }
`;

const DELETE_ORGANIZATION_QUERY = gql`
  mutation organizationDelete($id: ID!) {
    organizationDelete(id: $id)
  }
`;

const CREATE_RELATIONSHIP_QUERY = gql`
  mutation StixCoreRelationshipAdd($input: StixCoreRelationshipAddInput!) {
    stixCoreRelationshipAdd(input: $input) {
      id
    }
  }
`;

const LIST_RELATIONSHIPS_QUERY = gql`
  query StixCoreRelationships($search: String) {
    stixCoreRelationships(search: $search, first: 50) {
      edges {
        node {
          id
        }
      }
    }
  }
`;

const RESTRICTED_NAME = 'Searchrestrictedsecretorganization';
const ACCESSIBLE_NAME = 'Searchrestrictedpublicorganization';

describe('StixCoreRelationship search with restricted connections', () => {
  let restrictedOrganizationId: string;
  let accessibleOrganizationId: string;
  let relationshipId: string;

  beforeAll(async () => {
    const restricted = await queryAsAdminWithSuccess({
      query: CREATE_ORGANIZATION_QUERY,
      variables: { input: { name: RESTRICTED_NAME, objectMarking: [MARKING_TLP_RED] } },
    });
    restrictedOrganizationId = restricted.data?.organizationAdd.id;
    const accessible = await queryAsAdminWithSuccess({
      query: CREATE_ORGANIZATION_QUERY,
      variables: { input: { name: ACCESSIBLE_NAME } },
    });
    accessibleOrganizationId = accessible.data?.organizationAdd.id;
    const relationship = await queryAsAdminWithSuccess({
      query: CREATE_RELATIONSHIP_QUERY,
      variables: { input: { fromId: restrictedOrganizationId, toId: accessibleOrganizationId, relationship_type: 'related-to' } },
    });
    relationshipId = relationship.data?.stixCoreRelationshipAdd.id;
  });

  afterAll(async () => {
    await queryAsAdminWithSuccess({ query: DELETE_ORGANIZATION_QUERY, variables: { id: restrictedOrganizationId } });
    await queryAsAdminWithSuccess({ query: DELETE_ORGANIZATION_QUERY, variables: { id: accessibleOrganizationId } });
  });

  it('should find the relationship by the name of a connection the user can access', async () => {
    const adminResult = await queryAsAdminWithSuccess({ query: LIST_RELATIONSHIPS_QUERY, variables: { search: RESTRICTED_NAME } });
    expect(adminResult.data?.stixCoreRelationships.edges.map((e: { node: { id: string } }) => e.node.id)).toEqual([relationshipId]);
    const userResult = await queryAsUserWithSuccess(USER_EDITOR, { query: LIST_RELATIONSHIPS_QUERY, variables: { search: ACCESSIBLE_NAME } });
    expect(userResult.data?.stixCoreRelationships.edges.map((e: { node: { id: string } }) => e.node.id)).toEqual([relationshipId]);
  });

  it('should not find the relationship by the name or id of a connection the user cannot access', async () => {
    const byName = await queryAsUserWithSuccess(USER_EDITOR, { query: LIST_RELATIONSHIPS_QUERY, variables: { search: RESTRICTED_NAME } });
    expect(byName.data?.stixCoreRelationships.edges.length).toEqual(0);
    const byExactName = await queryAsUserWithSuccess(USER_EDITOR, { query: LIST_RELATIONSHIPS_QUERY, variables: { search: `"${RESTRICTED_NAME}"` } });
    expect(byExactName.data?.stixCoreRelationships.edges.length).toEqual(0);
    const byId = await queryAsUserWithSuccess(USER_EDITOR, { query: LIST_RELATIONSHIPS_QUERY, variables: { search: restrictedOrganizationId } });
    expect(byId.data?.stixCoreRelationships.edges.length).toEqual(0);
  });
});
