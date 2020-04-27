import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';

const LIST_QUERY = gql`
  query sectors(
    $first: Int
    $after: ID
    $orderBy: SectorsOrdering
    $orderMode: OrderingMode
    $filters: [SectorsFiltering]
    $filterMode: FilterMode
    $search: String
  ) {
    sectors(
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
  query sector($id: String!) {
    sector(id: $id) {
      id
      name
      description
      subSectors {
        edges {
          node {
            id
          }
        }
      }
      parentSectors {
        edges {
          node {
            id
          }
        }
      }
      isSubSector
      toStix
    }
  }
`;

describe('Sector resolver standard behavior', () => {
  let sectorInternalId;
  let sectorMarkingDefinitionRelationId;
  const sectorStixId = 'identity--be5c22c3-b130-4c6e-9545-10a0114d0908';
  it('should sector created', async () => {
    const CREATE_QUERY = gql`
      mutation SectorAdd($input: SectorAddInput) {
        sectorAdd(input: $input) {
          id
          name
          description
        }
      }
    `;
    // Create the sector
    const SECTOR_TO_CREATE = {
      input: {
        name: 'Sector',
        stix_id_key: sectorStixId,
        description: 'Sector description',
      },
    };
    const sector = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: SECTOR_TO_CREATE,
    });
    expect(sector).not.toBeNull();
    expect(sector.data.sectorAdd).not.toBeNull();
    expect(sector.data.sectorAdd.name).toEqual('Sector');
    sectorInternalId = sector.data.sectorAdd.id;
  });
  it('should sector loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: sectorInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.sector).not.toBeNull();
    expect(queryResult.data.sector.id).toEqual(sectorInternalId);
    expect(queryResult.data.sector.toStix.length).toBeGreaterThan(5);
  });
  it('should sector loaded by stix id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: sectorStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.sector).not.toBeNull();
    expect(queryResult.data.sector.id).toEqual(sectorInternalId);
  });
  it('should sector subsectors be accurate', async () => {
    const queryResult = await queryAsAdmin({
      query: READ_QUERY,
      variables: { id: '9dcde1a4-88ef-4f50-ad74-23d865b438e6' },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.sector).not.toBeNull();
    expect(queryResult.data.sector.id).toEqual('9dcde1a4-88ef-4f50-ad74-23d865b438e6');
    expect(queryResult.data.sector.isSubSector).toBeFalsy();
    expect(queryResult.data.sector.subSectors.edges.length).toEqual(1);
    expect(queryResult.data.sector.subSectors.edges[0].node.id).toEqual('b9c8cb0f-607c-4cb3-aa20-2450eaa8c3c4');
  });
  it('should sector parent sectors be accurate', async () => {
    const queryResult = await queryAsAdmin({
      query: READ_QUERY,
      variables: { id: 'b9c8cb0f-607c-4cb3-aa20-2450eaa8c3c4' },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.sector).not.toBeNull();
    expect(queryResult.data.sector.id).toEqual('b9c8cb0f-607c-4cb3-aa20-2450eaa8c3c4');
    expect(queryResult.data.sector.isSubSector).toBeTruthy();
    expect(queryResult.data.sector.parentSectors.edges.length).toEqual(1);
    expect(queryResult.data.sector.parentSectors.edges[0].node.id).toEqual('9dcde1a4-88ef-4f50-ad74-23d865b438e6');
  });
  it('should list sectors', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.sectors.edges.length).toEqual(4);
  });
  it('should update sector', async () => {
    const UPDATE_QUERY = gql`
      mutation SectorEdit($id: ID!, $input: EditInput!) {
        sectorEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            name
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: sectorInternalId, input: { key: 'name', value: ['Sector - test'] } },
    });
    expect(queryResult.data.sectorEdit.fieldPatch.name).toEqual('Sector - test');
  });
  it('should context patch sector', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation SectorEdit($id: ID!, $input: EditContext) {
        sectorEdit(id: $id) {
          contextPatch(input: $input) {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: sectorInternalId, input: { focusOn: 'description' } },
    });
    expect(queryResult.data.sectorEdit.contextPatch.id).toEqual(sectorInternalId);
  });
  it('should context clean sector', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation SectorEdit($id: ID!) {
        sectorEdit(id: $id) {
          contextClean {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: sectorInternalId },
    });
    expect(queryResult.data.sectorEdit.contextClean.id).toEqual(sectorInternalId);
  });
  it('should add relation in sector', async () => {
    const RELATION_ADD_QUERY = gql`
      mutation SectorEdit($id: ID!, $input: RelationAddInput!) {
        sectorEdit(id: $id) {
          relationAdd(input: $input) {
            id
            from {
              ... on Sector {
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
        id: sectorInternalId,
        input: {
          fromRole: 'so',
          toRole: 'marking',
          toId: '43f586bc-bcbc-43d1-ab46-43e5ab1a2c46',
          through: 'object_marking_refs',
        },
      },
    });
    expect(queryResult.data.sectorEdit.relationAdd.from.markingDefinitions.edges.length).toEqual(1);
    sectorMarkingDefinitionRelationId =
      queryResult.data.sectorEdit.relationAdd.from.markingDefinitions.edges[0].relation.id;
  });
  it('should delete relation in sector', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation SectorEdit($id: ID!, $relationId: ID!) {
        sectorEdit(id: $id) {
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
        id: sectorInternalId,
        relationId: sectorMarkingDefinitionRelationId,
      },
    });
    expect(queryResult.data.sectorEdit.relationDelete.markingDefinitions.edges.length).toEqual(0);
  });
  it('should sector deleted', async () => {
    const DELETE_QUERY = gql`
      mutation sectorDelete($id: ID!) {
        sectorEdit(id: $id) {
          delete
        }
      }
    `;
    // Delete the sector
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: sectorInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: sectorStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.sector).toBeNull();
  });
});
