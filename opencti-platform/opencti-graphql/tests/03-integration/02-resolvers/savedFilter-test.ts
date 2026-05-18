import { describe, it, expect, beforeAll } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, testContext, USER_EDITOR } from '../../utils/testQuery';
import { queryAsAdminWithSuccess, queryAsUser, queryAsUserWithSuccess } from '../../utils/testQueryHelper';
import { elLoadById } from '../../../src/database/engine';
import { MEMBER_ACCESS_ALL } from '../../../src/utils/access';

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
    describe('If I use the addSavedFilter mutation', () => {
      it('should create a filter', async () => {
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
      });

      it('should have the creator as admin in authorized members', async () => {
        const result = await queryAsAdminWithSuccess({
          query: GET_SAVED_FILTERS_QUERY,
          variables: { first: 10 },
        });
        const savedFilters = result.data?.savedFilters.edges;
        const filter = savedFilters.find((e: any) => e.node.id === createdFilterId);
        expect(filter).toBeDefined();
        expect(filter.node.authorizedMembers).toBeDefined();
        expect(filter.node.authorizedMembers.length).toEqual(1);
        expect(filter.node.authorizedMembers[0].id).toEqual(ADMIN_USER.id);
        expect(filter.node.authorizedMembers[0].access_right).toEqual('admin');
      });
    });
  });

  describe('savedFilters', () => {
    describe('If I use the savedFilters query', () => {
      it('gives the list of saved filters', async () => {
        const result = await queryAsAdminWithSuccess({
          query: GET_SAVED_FILTERS_QUERY,
          variables: {},
        });

        const savedFilters = result.data?.savedFilters.edges;
        expect(savedFilters).toBeDefined();
        expect(savedFilters.length).toEqual(1);
      });
      it('gives the list of saved filters with restricted members', async () => {
        const result = await queryAsUserWithSuccess(USER_EDITOR, {
          query: GET_SAVED_FILTERS_QUERY,
          variables: {},
        });

        const savedFilters = result.data?.savedFilters.edges;
        expect(savedFilters).toBeDefined();
        expect(savedFilters.length).toEqual(0);
      });
    });
  });

  describe('savedFilterEdit', () => {
    describe('If I edit the filter of a saved Filter', async () => {
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
  });

  describe('savedFilterEditAuthorizedMembers (sharing)', () => {
    it('should not be visible to another user before sharing', async () => {
      const result = await queryAsUserWithSuccess(USER_EDITOR, {
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
      const result = await queryAsUserWithSuccess(USER_EDITOR, {
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
      const result = await queryAsUser(USER_EDITOR, {
        query: EDIT_AUTHORIZED_MEMBERS_MUTATION,
        variables: { id: createdFilterId, input },
      });
      expect(result.errors).toBeDefined();
      expect(result.errors!.length).toBeGreaterThan(0);
    });

    it('should not allow removing all admins from authorized members', async () => {
      const input = [
        { id: ADMIN_USER.id, access_right: 'view' },
        { id: MEMBER_ACCESS_ALL, access_right: 'view' },
      ];
      const result = await queryAsUser(USER_EDITOR, {
        query: EDIT_AUTHORIZED_MEMBERS_MUTATION,
        variables: { id: createdFilterId, input },
      });
      expect(result.errors).toBeDefined();
      expect(result.errors!.length).toBeGreaterThan(0);
      expect(result.errors![0].message).toEqual('It should have at least one valid member with admin access');
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
      const result = await queryAsUserWithSuccess(USER_EDITOR, {
        query: GET_SAVED_FILTERS_QUERY,
        variables: {},
      });
      const savedFilters = result.data?.savedFilters.edges;
      expect(savedFilters.length).toEqual(0);
    });
  });

  describe('savedFilterDelete', () => {
    describe('If I take the last created filter', () => {
      it('should have found the filter', async () => {
        const savedFilter = await elLoadById(testContext, ADMIN_USER, createdFilterId);
        expect(savedFilter).toBeDefined();
      });

      describe('If I use the deleteSavedFilter function', () => {
        beforeAll(async () => {
          await queryAsAdminWithSuccess({
            query: DELETE_SAVED_FILTER_MUTATION,
            variables: {
              id: createdFilterId,
            },
          });
        });

        it('should have deleted the last created filter', async () => {
          const savedFilter = await elLoadById(testContext, ADMIN_USER, createdFilterId);
          expect(savedFilter).toBeUndefined();
        });
      });
    });
  });
});
