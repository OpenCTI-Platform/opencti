import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';

const LIST_QUERY = gql`
  query regions(
    $first: Int
    $after: ID
    $orderBy: RegionsOrdering
    $orderMode: OrderingMode
    $filters: [RegionsFiltering]
    $filterMode: FilterMode
    $search: String
  ) {
    regions(
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
  query region($id: String!) {
    region(id: $id) {
      id
      name
      description
      subRegions {
        edges {
          node {
            id
          }
        }
      }
      parentRegions {
        edges {
          node {
            id
          }
        }
      }
      isSubRegion
      toStix
    }
  }
`;

describe('Region resolver standard behavior', () => {
  let regionInternalId;
  let regionMarkingDefinitionRelationId;
  const regionStixId = 'identity--e0afe8b4-8615-46cb-abe1-cf7e08c1f0ca';
  it('should region created', async () => {
    const CREATE_QUERY = gql`
      mutation RegionAdd($input: RegionAddInput) {
        regionAdd(input: $input) {
          id
          name
          description
        }
      }
    `;
    // Create the region
    const REGION_TO_CREATE = {
      input: {
        name: 'Region',
        stix_id_key: regionStixId,
        description: 'Region description',
      },
    };
    const region = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: REGION_TO_CREATE,
    });
    expect(region).not.toBeNull();
    expect(region.data.regionAdd).not.toBeNull();
    expect(region.data.regionAdd.name).toEqual('Region');
    regionInternalId = region.data.regionAdd.id;
  });
  it('should region loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: regionInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.region).not.toBeNull();
    expect(queryResult.data.region.id).toEqual(regionInternalId);
    expect(queryResult.data.region.toStix.length).toBeGreaterThan(5);
  });
  it('should region loaded by stix id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: regionStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.region).not.toBeNull();
    expect(queryResult.data.region.id).toEqual(regionInternalId);
  });
  it('should region subregions be accurate', async () => {
    const queryResult = await queryAsAdmin({
      query: READ_QUERY,
      variables: { id: '98cbf59d-f079-4eb9-8a88-2095d0d336c1' },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.region).not.toBeNull();
    expect(queryResult.data.region.id).toEqual('98cbf59d-f079-4eb9-8a88-2095d0d336c1');
    expect(queryResult.data.region.isSubRegion).toBeFalsy();
    expect(queryResult.data.region.subRegions.edges.length).toEqual(1);
    expect(queryResult.data.region.subRegions.edges[0].node.id).toEqual('ccbbd430-f264-4dae-b4db-d5c02e1edeb7');
  });
  it('should region parent regions be accurate', async () => {
    const queryResult = await queryAsAdmin({
      query: READ_QUERY,
      variables: { id: 'ccbbd430-f264-4dae-b4db-d5c02e1edeb7' },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.region).not.toBeNull();
    expect(queryResult.data.region.id).toEqual('ccbbd430-f264-4dae-b4db-d5c02e1edeb7');
    expect(queryResult.data.region.isSubRegion).toBeTruthy();
    expect(queryResult.data.region.parentRegions.edges.length).toEqual(1);
    expect(queryResult.data.region.parentRegions.edges[0].node.id).toEqual('98cbf59d-f079-4eb9-8a88-2095d0d336c1');
  });
  it('should list regions', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.regions.edges.length).toEqual(3);
  });
  it('should update region', async () => {
    const UPDATE_QUERY = gql`
      mutation RegionEdit($id: ID!, $input: EditInput!) {
        regionEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            name
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: regionInternalId, input: { key: 'name', value: ['Region - test'] } },
    });
    expect(queryResult.data.regionEdit.fieldPatch.name).toEqual('Region - test');
  });
  it('should context patch region', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation RegionEdit($id: ID!, $input: EditContext) {
        regionEdit(id: $id) {
          contextPatch(input: $input) {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: regionInternalId, input: { focusOn: 'description' } },
    });
    expect(queryResult.data.regionEdit.contextPatch.id).toEqual(regionInternalId);
  });
  it('should context clean region', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation RegionEdit($id: ID!) {
        regionEdit(id: $id) {
          contextClean {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: regionInternalId },
    });
    expect(queryResult.data.regionEdit.contextClean.id).toEqual(regionInternalId);
  });
  it('should add relation in region', async () => {
    const RELATION_ADD_QUERY = gql`
      mutation RegionEdit($id: ID!, $input: RelationAddInput!) {
        regionEdit(id: $id) {
          relationAdd(input: $input) {
            id
            from {
              ... on Region {
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
        id: regionInternalId,
        input: {
          fromRole: 'so',
          toRole: 'marking',
          toId: '43f586bc-bcbc-43d1-ab46-43e5ab1a2c46',
          through: 'object_marking_refs',
        },
      },
    });
    expect(queryResult.data.regionEdit.relationAdd.from.markingDefinitions.edges.length).toEqual(1);
    regionMarkingDefinitionRelationId =
      queryResult.data.regionEdit.relationAdd.from.markingDefinitions.edges[0].relation.id;
  });
  it('should delete relation in region', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation RegionEdit($id: ID!, $relationId: ID!) {
        regionEdit(id: $id) {
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
        id: regionInternalId,
        relationId: regionMarkingDefinitionRelationId,
      },
    });
    expect(queryResult.data.regionEdit.relationDelete.markingDefinitions.edges.length).toEqual(0);
  });
  it('should region deleted', async () => {
    const DELETE_QUERY = gql`
      mutation regionDelete($id: ID!) {
        regionEdit(id: $id) {
          delete
        }
      }
    `;
    // Delete the region
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: regionInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: regionStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.region).toBeNull();
  });
});
