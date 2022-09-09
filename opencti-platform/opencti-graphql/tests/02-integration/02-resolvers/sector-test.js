import gql from 'graphql-tag';
import { ADMIN_USER, queryAsAdmin } from '../../utils/testQuery';
import { elLoadById } from '../../../src/database/engine';

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
      standard_id
      name
      description
      subSectors {
        edges {
          node {
            id
            standard_id
          }
        }
      }
      parentSectors {
        edges {
          node {
            id
            standard_id
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
        stix_id: sectorStixId,
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
    const sector = await elLoadById(ADMIN_USER, 'identity--5556c4ab-3e5e-4d56-8410-60b29cecbeb6');
    const queryResult = await queryAsAdmin({
      query: READ_QUERY,
      variables: { id: sector.internal_id },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.sector).not.toBeNull();
    expect(queryResult.data.sector.standard_id).toEqual('identity--6e24d2a6-6ce1-5fbb-b3c6-e37f1dc381ff');
    expect(queryResult.data.sector.isSubSector).toBeFalsy();
    expect(queryResult.data.sector.subSectors.edges.length).toEqual(1);
    expect(queryResult.data.sector.subSectors.edges[0].node.standard_id).toEqual(
      'identity--bcd45704-00ab-5e55-b6b2-176bba1717bd'
    );
  });
  it('should sector parent sectors be accurate', async () => {
    const sector = await elLoadById(ADMIN_USER, 'identity--360f3368-b911-4bb1-a7f9-0a8e4ef4e023');
    const queryResult = await queryAsAdmin({
      query: READ_QUERY,
      variables: { id: sector.internal_id },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.sector).not.toBeNull();
    expect(queryResult.data.sector.standard_id).toEqual('identity--bcd45704-00ab-5e55-b6b2-176bba1717bd');
    expect(queryResult.data.sector.isSubSector).toBeTruthy();
    expect(queryResult.data.sector.parentSectors.edges.length).toEqual(1);
    expect(queryResult.data.sector.parentSectors.edges[0].node.standard_id).toEqual(
      'identity--6e24d2a6-6ce1-5fbb-b3c6-e37f1dc381ff'
    );
  });
  it('should list sectors', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.sectors.edges.length).toEqual(4);
  });
  it('should update sector', async () => {
    const UPDATE_QUERY = gql`
      mutation SectorEdit($id: ID!, $input: [EditInput]!) {
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
      mutation SectorEdit($id: ID!, $input: StixMetaRelationshipAddInput!) {
        sectorEdit(id: $id) {
          relationAdd(input: $input) {
            id
            from {
              ... on Sector {
                objectMarking {
                  edges {
                    node {
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
          toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
          relationship_type: 'object-marking',
        },
      },
    });
    expect(queryResult.data.sectorEdit.relationAdd.from.objectMarking.edges.length).toEqual(1);
  });
  it('should delete relation in sector', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation SectorEdit($id: ID!, $toId: StixRef!, $relationship_type: String!) {
        sectorEdit(id: $id) {
          relationDelete(toId: $toId, relationship_type: $relationship_type) {
            id
            objectMarking {
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
        toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
        relationship_type: 'object-marking',
      },
    });
    expect(queryResult.data.sectorEdit.relationDelete.objectMarking.edges.length).toEqual(0);
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
