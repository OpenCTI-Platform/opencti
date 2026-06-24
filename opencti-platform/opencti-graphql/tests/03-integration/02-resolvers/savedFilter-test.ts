import { describe, it, expect } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, testContext, USER_PARTICIPATE } from '../../utils/testQuery';
import { queryAsAdminWithError, queryAsAdminWithSuccess, queryAsUserIsExpectedForbidden, queryAsUserWithSuccess } from '../../utils/testQueryHelper';
import { elLoadById } from '../../../src/database/engine';
import { MEMBER_ACCESS_ALL } from '../../../src/utils/access';
import { ENTITY_TYPE_USER } from '../../../src/schema/internalObject';

const GET_SAVED_FILTERS_QUERY = gql`
  query savedFilters(
    $first: Int
    $after: ID
    $orderBy: SavedFilterOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $search: String
  ) {
    savedFilters(
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
          filters
          scope
          creator_id
          currentUserAccessRight
          authorizedMembers {
            id
            name
            entity_type
            access_right
          }
        }
      }
    }
  }
`;

const CREATE_SAVED_FILTER_MUTATION = gql`
  mutation savedFilterAdd($input: SavedFilterAddInput!) {
    savedFilterAdd(input: $input) {
      id
      name
      authorizedMembers {
        id
        name
        entity_type
        access_right
      }
    }
  }
`;

const DELETE_SAVED_FILTER_MUTATION = gql`
  mutation savedFilterDelete($id: ID!) {
    savedFilterDelete(id: $id) 
  }
`;

const EDIT_SAVED_FILTER_MUTATION = gql`
  mutation savedFilterEdit($id: ID!, $input: [EditInput!]!) {
    savedFilterFieldPatch(id: $id, input: $input) {
      id
      name
      filters
      scope
    }
  }
`;

const EDIT_AUTHORIZED_MEMBERS_MUTATION = gql`
  mutation savedFilterEditAuthorizedMembers($id: ID!, $input: [MemberAccessInput!]!) {
    savedFilterEditAuthorizedMembers(id: $id, input: $input) {
      id
      name
      authorizedMembers {
        id
        name
        entity_type
        access_right
      }
    }
  }
`;

describe('Saved Filter Resolver', () => {
  let createdFilterId: string = '';
  const newFilter = {
    mode: 'and',
    filters: [],
    filterGroups: [],
  };

  describe('savedFilterAdd', () => {
    it('should create a filter with the creator as admin in authorized members', async () => {
      const input = {
        name: 'my new filter',
        filters: JSON.stringify(newFilter),
        scope: 'Incident',
      };

      const result = await queryAsAdminWithSuccess({
        query: CREATE_SAVED_FILTER_MUTATION,
        variables: {
          input: { ...input },
        },
      });

      expect(result?.data?.savedFilterAdd).toBeDefined();
      expect(result?.data?.savedFilterAdd.name).toEqual('my new filter');
      createdFilterId = result?.data?.savedFilterAdd.id as string;

      const { authorizedMembers } = result.data.savedFilterAdd;
      expect(authorizedMembers).toBeDefined();
      expect(authorizedMembers.length).toEqual(1);
      expect(authorizedMembers[0].access_right).toEqual('admin');
    });

    it('should create a filter with creator as admin in authorized members even without KNOWLEDGE_KNSHAREFILTERS capability', async () => {
      const input = {
        name: 'filter without share capability',
        filters: JSON.stringify(newFilter),
        scope: 'Incident',
      };

      const result = await queryAsUserWithSuccess(USER_PARTICIPATE, {
        query: CREATE_SAVED_FILTER_MUTATION,
        variables: {
          input: { ...input },
        },
      });

      expect(result?.data?.savedFilterAdd).toBeDefined();
      expect(result?.data?.savedFilterAdd.name).toEqual('filter without share capability');

      const { authorizedMembers } = result.data.savedFilterAdd;
      expect(authorizedMembers.length).toEqual(1);
      expect(authorizedMembers[0].name).toEqual(USER_PARTICIPATE.email);
      expect(authorizedMembers[0].access_right).toEqual('admin');

      // Cleanup: delete the filter as the creator
      await queryAsUserWithSuccess(USER_PARTICIPATE, {
        query: DELETE_SAVED_FILTER_MUTATION,
        variables: { id: result.data.savedFilterAdd.id },
      });
    });
  });

  describe('savedFilters', () => {
    it('gives the list of saved filters', async () => {
      const result = await queryAsAdminWithSuccess({
        query: GET_SAVED_FILTERS_QUERY,
        variables: {},
      });
      const savedFilters = result.data?.savedFilters.edges;
      expect(savedFilters).toBeDefined();
      expect(savedFilters.length).toEqual(1);
      const myFilter = savedFilters[0].node;
      expect(myFilter.name).toEqual('my new filter');
      expect(myFilter.creator_id).toEqual(ADMIN_USER.id);
      expect(myFilter.currentUserAccessRight).toEqual('admin');
      expect(myFilter.authorizedMembers.length).toEqual(1);
      expect(myFilter.authorizedMembers[0].name).toEqual(ADMIN_USER.name);
      expect(myFilter.authorizedMembers[0].entity_type).toEqual(ENTITY_TYPE_USER);
      expect(myFilter.authorizedMembers[0].access_right).toEqual('admin');
    });
  });

  describe('savedFilterEdit', () => {
    const editedFilters = {
      ...newFilter,
      filters: [{ key: 'entity_type', operator: 'eq', mode: 'or', values: ['Task'] }],
    };
    const input = {
      key: 'filters',
      value: [JSON.stringify(editedFilters)],
    };

    it('should have a filter different than the initial value', async () => {
      const result = await queryAsAdminWithSuccess({
        query: EDIT_SAVED_FILTER_MUTATION,
        variables: {
          id: createdFilterId,
          input,
        },
      });
      expect(result?.data?.savedFilterFieldPatch?.filters).not.equal(JSON.stringify(newFilter));
    });
  });

  describe('savedFilterEditAuthorizedMembers (sharing)', () => {
    it('should not be visible to another user before sharing', async () => {
      const result = await queryAsUserWithSuccess(USER_PARTICIPATE, {
        query: GET_SAVED_FILTERS_QUERY,
        variables: {},
      });
      const savedFilters = result.data?.savedFilters.edges;
      expect(savedFilters.length).toEqual(0);
    });

    it('should share the saved filter with ALL members (view access)', async () => {
      const input = [
        { id: ADMIN_USER.id, access_right: 'admin' },
        { id: MEMBER_ACCESS_ALL, access_right: 'view' },
      ];
      const result = await queryAsAdminWithSuccess({
        query: EDIT_AUTHORIZED_MEMBERS_MUTATION,
        variables: { id: createdFilterId, input },
      });
      const authorizedMembers = result.data?.savedFilterEditAuthorizedMembers?.authorizedMembers;
      expect(authorizedMembers).toBeDefined();
      expect(authorizedMembers.length).toEqual(2);
      expect(authorizedMembers.some((m: any) => m.access_right === 'admin')).toBeTruthy();
      expect(authorizedMembers.some((m: any) => m.access_right === 'view')).toBeTruthy();
    });

    it('should be visible to another user after sharing with ALL', async () => {
      const result = await queryAsUserWithSuccess(USER_PARTICIPATE, {
        query: GET_SAVED_FILTERS_QUERY,
        variables: {},
      });
      const savedFilters = result.data?.savedFilters.edges;
      expect(savedFilters.length).toEqual(1);
      expect(savedFilters[0].node.id).toEqual(createdFilterId);
    });

    it('should expose currentUserAccessRight for the shared filter', async () => {
      const result = await queryAsAdminWithSuccess({
        query: GET_SAVED_FILTERS_QUERY,
        variables: { first: 10 },
      });
      const savedFilters = result.data?.savedFilters.edges;
      const filter = savedFilters.find((e: any) => e.node.id === createdFilterId);
      expect(filter).toBeDefined();
      expect(filter.node.currentUserAccessRight).toEqual('admin');
    });

    it('should not allow editing authorized members without valid admin', async () => {
      const input = [
        { id: 'non_existing_id', access_right: 'admin' },
      ];
      await queryAsAdminWithError({
        query: EDIT_AUTHORIZED_MEMBERS_MUTATION,
        variables: { id: createdFilterId, input },
      }, 'It should have at least one valid member with admin access', 'FUNCTIONAL_ERROR');
    });

    it('should not allow removing all admins from authorized members', async () => {
      const input = [
        { id: ADMIN_USER.id, access_right: 'view' },
        { id: MEMBER_ACCESS_ALL, access_right: 'view' },
      ];
      await queryAsAdminWithError({
        query: EDIT_AUTHORIZED_MEMBERS_MUTATION,
        variables: { id: createdFilterId, input },
      }, 'It should have at least one valid member with admin access', 'FUNCTIONAL_ERROR');
    });

    it('should not allow editing authorized members without "share filters" capability', async () => {
      const input = [
        { id: ADMIN_USER.id, access_right: 'admin' },
      ];
      await queryAsUserIsExpectedForbidden(USER_PARTICIPATE, {
        query: EDIT_AUTHORIZED_MEMBERS_MUTATION,
        variables: { id: createdFilterId, input },
      });
    });

    it('should revoke sharing (restrict back to creator only)', async () => {
      const input = [
        { id: ADMIN_USER.id, access_right: 'admin' },
      ];
      const result = await queryAsAdminWithSuccess({
        query: EDIT_AUTHORIZED_MEMBERS_MUTATION,
        variables: { id: createdFilterId, input },
      });
      const authorizedMembers = result.data?.savedFilterEditAuthorizedMembers?.authorizedMembers;
      expect(authorizedMembers.length).toEqual(1);
    });

    it('should no longer be visible to another user after revoking sharing', async () => {
      const result = await queryAsUserWithSuccess(USER_PARTICIPATE, {
        query: GET_SAVED_FILTERS_QUERY,
        variables: {},
      });
      const savedFilters = result.data?.savedFilters.edges;
      expect(savedFilters.length).toEqual(0);
    });
  });

  describe('savedFilterDelete', () => {
    it('should not allow a non-creator user without share filter capability to delete a filter they can manage', async () => {
      // Share the filter with admin rights with ALL members so USER_PARTICIPATE can manage it
      const shareInput = [
        { id: ADMIN_USER.id, access_right: 'admin' },
        { id: MEMBER_ACCESS_ALL, access_right: 'admin' },
      ];
      await queryAsAdminWithSuccess({
        query: EDIT_AUTHORIZED_MEMBERS_MUTATION,
        variables: { id: createdFilterId, input: shareInput },
      });

      // Verify USER_PARTICIPATE can see the filter
      const listResult = await queryAsUserWithSuccess(USER_PARTICIPATE, {
        query: GET_SAVED_FILTERS_QUERY,
        variables: {},
      });
      expect(listResult.data?.savedFilters.edges.length).toEqual(1);

      // USER_PARTICIPATE can manage the filter but lacks KNOWLEDGE_KNSHAREFILTERS capability
      await queryAsUserIsExpectedForbidden(USER_PARTICIPATE, {
        query: DELETE_SAVED_FILTER_MUTATION,
        variables: { id: createdFilterId },
      });
    });

    it('should delete a saved filter', async () => {
      await queryAsAdminWithSuccess({
        query: DELETE_SAVED_FILTER_MUTATION,
        variables: {
          id: createdFilterId,
        },
      });
      const savedFilter = await elLoadById(testContext, ADMIN_USER, createdFilterId);
      expect(savedFilter).toBeUndefined();
    });
  });
});
