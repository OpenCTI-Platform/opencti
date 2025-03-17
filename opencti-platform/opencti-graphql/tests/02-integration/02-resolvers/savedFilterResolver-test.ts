import { describe, it, expect, beforeAll } from 'vitest';
import gql from 'graphql-tag';
import type { SavedFilter } from 'src/generated/graphql';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { queryAsAdminWithSuccess } from '../../utils/testQueryHelper';
import { elLoadById } from '../../../src/database/engine';

const GET_SAVED_FILTERS_QUERY = gql`
  query savedFilters(
    $first: Int
    $after: ID
    $orderBy: ExclusionListOrdering
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

describe('Saved Filter Resolver', () => {
  let createdFilterId: string = '';
  const newFilter = {
    mode: 'and',
    filters: [],
    filterGroups: [],
  };

  describe('addSavedFilter', () => {
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
      it('gives the saved filter list', async () => {
        const result = await queryAsAdminWithSuccess({
          query: GET_SAVED_FILTERS_QUERY,
          variables: {},
        });

        const savedFilters = result.data?.savedFilters.edges;
        expect(savedFilters).toBeDefined();
        expect(savedFilters.length).toEqual(1);
      });
    });
  });

  describe('deleteSavedFilter', () => {
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
