import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';

const LIST_QUERY = gql`
  query cities(
    $first: Int
    $after: ID
    $orderBy: CitiesOrdering
    $orderMode: OrderingMode
    $filters: [CitiesFiltering]
    $filterMode: FilterMode
    $search: String
  ) {
    cities(
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
  query city($id: String!) {
    city(id: $id) {
      id
      name
      description
      toStix
    }
  }
`;

describe('City resolver standard behavior', () => {
  let cityInternalId;
  let cityMarkingDefinitionRelationId;
  const cityStixId = 'identity--861af688-581e-4571-a0d9-955c9096fb41';
  it('should city created', async () => {
    const CREATE_QUERY = gql`
      mutation CityAdd($input: CityAddInput) {
        cityAdd(input: $input) {
          id
          name
          description
        }
      }
    `;
    // Create the city
    const CITY_TO_CREATE = {
      input: {
        name: 'City',
        stix_id_key: cityStixId,
        description: 'City description',
      },
    };
    const city = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: CITY_TO_CREATE,
    });
    expect(city).not.toBeNull();
    expect(city.data.cityAdd).not.toBeNull();
    expect(city.data.cityAdd.name).toEqual('City');
    cityInternalId = city.data.cityAdd.id;
  });
  it('should city loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: cityInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.city).not.toBeNull();
    expect(queryResult.data.city.id).toEqual(cityInternalId);
    expect(queryResult.data.city.toStix.length).toBeGreaterThan(5);
  });
  it('should city loaded by stix id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: cityStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.city).not.toBeNull();
    expect(queryResult.data.city.id).toEqual(cityInternalId);
  });
  it('should list cities', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.cities.edges.length).toEqual(2);
  });
  it('should update city', async () => {
    const UPDATE_QUERY = gql`
      mutation CityEdit($id: ID!, $input: EditInput!) {
        cityEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            name
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: cityInternalId, input: { key: 'name', value: ['City - test'] } },
    });
    expect(queryResult.data.cityEdit.fieldPatch.name).toEqual('City - test');
  });
  it('should context patch city', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation CityEdit($id: ID!, $input: EditContext) {
        cityEdit(id: $id) {
          contextPatch(input: $input) {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: cityInternalId, input: { focusOn: 'description' } },
    });
    expect(queryResult.data.cityEdit.contextPatch.id).toEqual(cityInternalId);
  });
  it('should context clean city', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation CityEdit($id: ID!) {
        cityEdit(id: $id) {
          contextClean {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: cityInternalId },
    });
    expect(queryResult.data.cityEdit.contextClean.id).toEqual(cityInternalId);
  });
  it('should add relation in city', async () => {
    const RELATION_ADD_QUERY = gql`
      mutation CityEdit($id: ID!, $input: RelationAddInput!) {
        cityEdit(id: $id) {
          relationAdd(input: $input) {
            id
            from {
              ... on City {
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
        id: cityInternalId,
        input: {
          fromRole: 'so',
          toRole: 'marking',
          toId: '43f586bc-bcbc-43d1-ab46-43e5ab1a2c46',
          through: 'object_marking_refs',
        },
      },
    });
    expect(queryResult.data.cityEdit.relationAdd.from.markingDefinitions.edges.length).toEqual(1);
    cityMarkingDefinitionRelationId =
      queryResult.data.cityEdit.relationAdd.from.markingDefinitions.edges[0].relation.id;
  });
  it('should delete relation in city', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation CityEdit($id: ID!, $relationId: ID!) {
        cityEdit(id: $id) {
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
        id: cityInternalId,
        relationId: cityMarkingDefinitionRelationId,
      },
    });
    expect(queryResult.data.cityEdit.relationDelete.markingDefinitions.edges.length).toEqual(0);
  });
  it('should city deleted', async () => {
    const DELETE_QUERY = gql`
      mutation cityDelete($id: ID!) {
        cityEdit(id: $id) {
          delete
        }
      }
    `;
    // Delete the city
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: cityInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: cityStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.city).toBeNull();
  });
});
