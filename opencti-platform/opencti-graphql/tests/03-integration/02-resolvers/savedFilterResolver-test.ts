import { describe, it, expect, beforeAll } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, testContext, USER_EDITOR } from '../../utils/testQuery';
import { queryAsAdminWithSuccess, queryAsUserWithSuccess } from '../../utils/testQueryHelper';
import { elLoadById } from '../../../src/database/engine';

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
          scope: 'Incident'
        };

        const result = await queryAsAdminWithSuccess({
          query: CREATE_SAVED_FILTER_MUTATION,
          variables: {
            input: { ...input }
          },
        });

        expect(result?.data?.savedFilterAdd).toBeDefined();
        expect(result?.data?.savedFilterAdd.name).toEqual('my new filter');
        createdFilterId = result?.data?.savedFilterAdd.id as string;
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
        const result = await queryAsUserWithSuccess(USER_EDITOR.client, {
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
        filters: [{ key: 'entity_type', operator: 'eq', mode: 'or', values: ['Task'] }]
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
              id: createdFilterId
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
