import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, getAuthUser, testContext, USER_EDITOR } from '../utils/testQuery';
import { queryAsAdminWithSuccess, queryAsUserWithSuccess } from '../utils/testQueryHelper';
import { MARKING_TLP_RED } from '../../src/schema/identifier';
import { findRefRelationshipsPaginated } from '../../src/domain/stixRefRelationship';
import type { AuthUser } from '../../src/types/user';

const CREATE_ORGANIZATION_QUERY = gql`
  mutation OrganizationAdd($input: OrganizationAddInput!) {
    organizationAdd(input: $input) {
      id
    }
  }
`;

const CREATE_ATTACK_PATTERN_QUERY = gql`
  mutation AttackPatternAdd($input: AttackPatternAddInput!) {
    attackPatternAdd(input: $input) {
      id
    }
  }
`;

const CREATE_REGISTRY_KEY_QUERY = gql`
  mutation StixCyberObservableAdd($objectMarking: [String], $WindowsRegistryKey: WindowsRegistryKeyAddInput) {
    stixCyberObservableAdd(type: "Windows-Registry-Key", objectMarking: $objectMarking, WindowsRegistryKey: $WindowsRegistryKey) {
      id
    }
  }
`;

const CREATE_REPORT_QUERY = gql`
  mutation ReportAdd($input: ReportAddInput!) {
    reportAdd(input: $input) {
      id
    }
  }
`;

const CREATE_RELATIONSHIP_QUERY = gql`
  mutation StixCoreRelationshipAdd($input: StixCoreRelationshipAddInput!) {
    stixCoreRelationshipAdd(input: $input) {
      id
    }
  }
`;

const DELETE_DOMAIN_OBJECT_QUERY = gql`
  mutation StixDomainObjectDelete($id: ID!) {
    stixDomainObjectEdit(id: $id) {
      delete
    }
  }
`;

const DELETE_OBSERVABLE_QUERY = gql`
  mutation StixCyberObservableDelete($id: ID!) {
    stixCyberObservableEdit(id: $id) {
      delete
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

const RESTRICTED_ORGANIZATION_NAME = 'Searchrestrictedsecretorganization';
const RESTRICTED_ATTACK_PATTERN_NAME = '"[T9157] Searchrestrictedattackpattern"';
const RESTRICTED_REGISTRY_KEY = 'Searchrestrictedregistrykey';
const ACCESSIBLE_NAME = 'Searchrestrictedpublicorganization';

type RelationshipsResult = { data?: Record<string, any> | null };
const relationshipIds = (result: RelationshipsResult) => result.data?.stixCoreRelationships.edges.map((e: { node: { id: string } }) => e.node.id).sort();

describe('Relationships search with restricted connections', () => {
  let editorAuthUser: AuthUser;
  let restrictedOrganizationId: string;
  let restrictedAttackPatternId: string;
  let restrictedRegistryKeyId: string;
  let accessibleOrganizationId: string;
  let reportId: string;
  const relationshipIdsBySource: Record<string, string> = {};

  beforeAll(async () => {
    editorAuthUser = await getAuthUser(USER_EDITOR.id);
    const restrictedOrganization = await queryAsAdminWithSuccess({
      query: CREATE_ORGANIZATION_QUERY,
      variables: { input: { name: RESTRICTED_ORGANIZATION_NAME, objectMarking: [MARKING_TLP_RED] } },
    });
    restrictedOrganizationId = restrictedOrganization.data?.organizationAdd.id;
    const restrictedAttackPattern = await queryAsAdminWithSuccess({
      query: CREATE_ATTACK_PATTERN_QUERY,
      variables: { input: { name: 'Searchrestrictedattackpattern', x_mitre_id: 'T9157', objectMarking: [MARKING_TLP_RED] } },
    });
    restrictedAttackPatternId = restrictedAttackPattern.data?.attackPatternAdd.id;
    // The representative of a registry key is its attribute_key, which is not a standard search field
    const restrictedRegistryKey = await queryAsAdminWithSuccess({
      query: CREATE_REGISTRY_KEY_QUERY,
      variables: { objectMarking: [MARKING_TLP_RED], WindowsRegistryKey: { attribute_key: RESTRICTED_REGISTRY_KEY } },
    });
    restrictedRegistryKeyId = restrictedRegistryKey.data?.stixCyberObservableAdd.id;
    const accessibleOrganization = await queryAsAdminWithSuccess({
      query: CREATE_ORGANIZATION_QUERY,
      variables: { input: { name: ACCESSIBLE_NAME } },
    });
    accessibleOrganizationId = accessibleOrganization.data?.organizationAdd.id;
    for (const fromId of [restrictedOrganizationId, restrictedAttackPatternId, restrictedRegistryKeyId]) {
      const relationship = await queryAsAdminWithSuccess({
        query: CREATE_RELATIONSHIP_QUERY,
        variables: { input: { fromId, toId: accessibleOrganizationId, relationship_type: 'related-to' } },
      });
      relationshipIdsBySource[fromId] = relationship.data?.stixCoreRelationshipAdd.id;
    }
    // Accessible report created by the restricted organization, connected through a created-by ref relationship
    const report = await queryAsAdminWithSuccess({
      query: CREATE_REPORT_QUERY,
      variables: { input: { name: ACCESSIBLE_NAME, published: '2026-01-01T00:00:00.000Z', createdBy: restrictedOrganizationId } },
    });
    reportId = report.data?.reportAdd.id;
  });

  afterAll(async () => {
    await queryAsAdminWithSuccess({ query: DELETE_DOMAIN_OBJECT_QUERY, variables: { id: reportId } });
    await queryAsAdminWithSuccess({ query: DELETE_DOMAIN_OBJECT_QUERY, variables: { id: restrictedOrganizationId } });
    await queryAsAdminWithSuccess({ query: DELETE_DOMAIN_OBJECT_QUERY, variables: { id: restrictedAttackPatternId } });
    await queryAsAdminWithSuccess({ query: DELETE_OBSERVABLE_QUERY, variables: { id: restrictedRegistryKeyId } });
    await queryAsAdminWithSuccess({ query: DELETE_DOMAIN_OBJECT_QUERY, variables: { id: accessibleOrganizationId } });
  });

  it('should find the relationships by the name of a connection the user can access', async () => {
    const userResult = await queryAsUserWithSuccess(USER_EDITOR.client, { query: LIST_RELATIONSHIPS_QUERY, variables: { search: ACCESSIBLE_NAME } });
    expect(relationshipIds(userResult)).toEqual(Object.values(relationshipIdsBySource).sort());
  });

  it.each([
    ['name', () => RESTRICTED_ORGANIZATION_NAME, () => restrictedOrganizationId],
    ['exact name', () => `"${RESTRICTED_ORGANIZATION_NAME}"`, () => restrictedOrganizationId],
    ['id', () => restrictedOrganizationId, () => restrictedOrganizationId],
    ['composite name', () => RESTRICTED_ATTACK_PATTERN_NAME, () => restrictedAttackPatternId],
    ['observable value', () => RESTRICTED_REGISTRY_KEY, () => restrictedRegistryKeyId],
  ])('should not find the relationship by the %s of a connection the user cannot access', async (_, getSearch, getSourceId) => {
    const variables = { search: getSearch() };
    // Other data can match too, as an id is searched by its fragments
    const relationshipId = relationshipIdsBySource[getSourceId()];
    const adminResult = await queryAsAdminWithSuccess({ query: LIST_RELATIONSHIPS_QUERY, variables });
    expect(relationshipIds(adminResult)).toContain(relationshipId);
    const userResult = await queryAsUserWithSuccess(USER_EDITOR.client, { query: LIST_RELATIONSHIPS_QUERY, variables });
    expect(relationshipIds(userResult)).not.toContain(relationshipId);
  });

  it('should not find a ref relationship by the name of a connection the user cannot access', async () => {
    const search = { search: RESTRICTED_ORGANIZATION_NAME };
    const adminResult = await findRefRelationshipsPaginated(testContext, ADMIN_USER, search);
    expect(adminResult.edges.some((e: { node: { fromId: string } }) => e.node.fromId === reportId)).toBe(true);
    const userResult = await findRefRelationshipsPaginated(testContext, editorAuthUser, search);
    expect(userResult.edges.some((e: { node: { fromId: string } }) => e.node.fromId === reportId)).toBe(false);
  });
});
