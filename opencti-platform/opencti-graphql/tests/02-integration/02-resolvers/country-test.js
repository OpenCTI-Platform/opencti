import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';

const LIST_QUERY = gql`
  query countries(
    $first: Int
    $after: ID
    $orderBy: CountriesOrdering
    $orderMode: OrderingMode
    $filters: [CountriesFiltering]
    $filterMode: FilterMode
    $search: String
  ) {
    countries(
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
  query country($id: String!) {
    country(id: $id) {
      id
      name
      description
      region {
        id
      }
      toStix
    }
  }
`;

describe('Country resolver standard behavior', () => {
  let countryInternalId;
  let countryMarkingDefinitionRelationId;
  const countryStixId = 'identity--93b1ee77-79d0-461d-8096-7c83b7a77646';
  it('should country created', async () => {
    const CREATE_QUERY = gql`
      mutation CountryAdd($input: CountryAddInput) {
        countryAdd(input: $input) {
          id
          name
          description
        }
      }
    `;
    // Create the country
    const COUNTRY_TO_CREATE = {
      input: {
        name: 'Country',
        stix_id_key: countryStixId,
        description: 'Country description',
      },
    };
    const country = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: COUNTRY_TO_CREATE,
    });
    expect(country).not.toBeNull();
    expect(country.data.countryAdd).not.toBeNull();
    expect(country.data.countryAdd.name).toEqual('Country');
    countryInternalId = country.data.countryAdd.id;
  });
  it('should country loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: countryInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.country).not.toBeNull();
    expect(queryResult.data.country.id).toEqual(countryInternalId);
  });
  it('should country loaded by stix id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: countryStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.country).not.toBeNull();
    expect(queryResult.data.country.id).toEqual(countryInternalId);
  });
  it('should country region be accurate', async () => {
    const queryResult = await queryAsAdmin({
      query: READ_QUERY,
      variables: { id: 'f2ea7d37-996d-4313-8f73-42a8782d39a0' },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.country).not.toBeNull();
    expect(queryResult.data.country.id).toEqual('f2ea7d37-996d-4313-8f73-42a8782d39a0');
    expect(queryResult.data.country.region).not.toBeNull();
    expect(queryResult.data.country.region.id).toEqual('ccbbd430-f264-4dae-b4db-d5c02e1edeb7');
  });
  it('should list countries', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.countries.edges.length).toEqual(2);
  });
  it('should update country', async () => {
    const UPDATE_QUERY = gql`
      mutation CountryEdit($id: ID!, $input: EditInput!) {
        countryEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            name
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: countryInternalId, input: { key: 'name', value: ['Country - test'] } },
    });
    expect(queryResult.data.countryEdit.fieldPatch.name).toEqual('Country - test');
  });
  it('should context patch country', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation CountryEdit($id: ID!, $input: EditContext) {
        countryEdit(id: $id) {
          contextPatch(input: $input) {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: countryInternalId, input: { focusOn: 'description' } },
    });
    expect(queryResult.data.countryEdit.contextPatch.id).toEqual(countryInternalId);
  });
  it('should context clean country', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation CountryEdit($id: ID!) {
        countryEdit(id: $id) {
          contextClean {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: countryInternalId },
    });
    expect(queryResult.data.countryEdit.contextClean.id).toEqual(countryInternalId);
  });
  it('should add relation in country', async () => {
    const RELATION_ADD_QUERY = gql`
      mutation CountryEdit($id: ID!, $input: RelationAddInput!) {
        countryEdit(id: $id) {
          relationAdd(input: $input) {
            id
            from {
              ... on Country {
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
        id: countryInternalId,
        input: {
          fromRole: 'so',
          toRole: 'marking',
          toId: '43f586bc-bcbc-43d1-ab46-43e5ab1a2c46',
          through: 'object_marking_refs',
        },
      },
    });
    expect(queryResult.data.countryEdit.relationAdd.from.markingDefinitions.edges.length).toEqual(1);
    countryMarkingDefinitionRelationId =
      queryResult.data.countryEdit.relationAdd.from.markingDefinitions.edges[0].relation.id;
  });
  it('should delete relation in country', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation CountryEdit($id: ID!, $relationId: ID!) {
        countryEdit(id: $id) {
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
        id: countryInternalId,
        relationId: countryMarkingDefinitionRelationId,
      },
    });
    expect(queryResult.data.countryEdit.relationDelete.markingDefinitions.edges.length).toEqual(0);
  });
  it('should country deleted', async () => {
    const DELETE_QUERY = gql`
      mutation countryDelete($id: ID!) {
        countryEdit(id: $id) {
          delete
        }
      }
    `;
    // Delete the country
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: countryInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: countryStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.country).toBeNull();
  });
});
