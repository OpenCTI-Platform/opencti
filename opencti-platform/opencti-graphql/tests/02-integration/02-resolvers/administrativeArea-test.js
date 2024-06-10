import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, editorQuery, testContext, USER_PARTICIPATE } from '../../utils/testQuery';
import { elLoadById } from '../../../src/database/engine';
import { MARKING_TLP_GREEN, MARKING_TLP_RED } from '../../../src/schema/identifier';
import { queryAsUserIsExpectedForbidden } from '../../utils/testQueryHelper';

const LIST_QUERY = gql`
  query administrativeAreas(
    $first: Int
    $after: ID
    $orderBy: AdministrativeAreasOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $search: String
  ) {
    administrativeAreas(
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
          description
        }
      }
    }
  }
`;

const READ_QUERY = gql`
  query administrativeArea($id: String!) {
    administrativeArea(id: $id) {
      id
      standard_id
      name
      description
      toStix
      country {
       name
      }
    }
  }
`;

describe('AdministrativeArea resolver standard behavior', () => {
  let administrativeAreaInternalId;
  const administrativeAreaStixId = 'location--5d80df0f-a57a-41e4-8645-db343701f756';
  it('Participant should fail administrativeArea creation', async () => {
    const CREATE_QUERY = gql`
        mutation AdministrativeAreaAdd($input: AdministrativeAreaAddInput!) {
            administrativeAreaAdd(input: $input) {
                id
                name
                description
            }
        }
    `;
    // Create the administrativeArea
    const ADMINISTRATIVEAREA_TO_CREATE = {
      input: {
        name: 'Administrative-Area',
        stix_id: administrativeAreaStixId,
        description: 'Administrative-Area description',
      },
    };
    await queryAsUserIsExpectedForbidden(USER_PARTICIPATE.client, {
      query: CREATE_QUERY,
      variables: ADMINISTRATIVEAREA_TO_CREATE,
    });
  });
  it('Editor should fail administrativeArea creation', async () => {
    const CREATE_QUERY = gql`
        mutation AdministrativeAreaAdd($input: AdministrativeAreaAddInput!) {
            administrativeAreaAdd(input: $input) {
                id
                name
                description
            }
        }
    `;
    // Create the administrativeArea
    const ADMINISTRATIVEAREA_TO_CREATE = {
      input: {
        name: 'Administrative-Area',
        stix_id: administrativeAreaStixId,
        description: 'Administrative-Area description',
        objectMarking: [MARKING_TLP_RED]
      },
    };
    const queryResult = await editorQuery({
      query: CREATE_QUERY,
      variables: ADMINISTRATIVEAREA_TO_CREATE,
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.errors.length).toEqual(1);
    expect(queryResult.errors.at(0).extensions.code).toEqual('MISSING_REFERENCE_ERROR');
  });
  it('should administrativeArea created', async () => {
    const CREATE_QUERY = gql`
      mutation AdministrativeAreaAdd($input: AdministrativeAreaAddInput!) {
        administrativeAreaAdd(input: $input) {
          id
          name
          description
        }
      }
    `;
    // Create the administrativeArea
    const ADMINISTRATIVEAREA_TO_CREATE = {
      input: {
        name: 'Administrative-Area',
        stix_id: administrativeAreaStixId,
        description: 'Administrative-Area description',
      },
    };
    const queryResult = await editorQuery({
      query: CREATE_QUERY,
      variables: ADMINISTRATIVEAREA_TO_CREATE,
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.administrativeAreaAdd).not.toBeNull();
    expect(queryResult.data.administrativeAreaAdd.name).toEqual('Administrative-Area');
    administrativeAreaInternalId = queryResult.data.administrativeAreaAdd.id; // bc1f31d7-4d9d-4754-89b1-9a7813c7c521
  });
  it('should administrativeArea loaded by internal id', async () => {
    const queryResult = await editorQuery({ query: READ_QUERY, variables: { id: administrativeAreaInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.administrativeArea).not.toBeNull();
    expect(queryResult.data.administrativeArea.id).toEqual(administrativeAreaInternalId);
    expect(queryResult.data.administrativeArea.toStix.length).toBeGreaterThan(5);
  });
  it('should administrativeArea loaded by stix id', async () => {
    const queryResult = await editorQuery({ query: READ_QUERY, variables: { id: administrativeAreaStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.administrativeArea).not.toBeNull();
    expect(queryResult.data.administrativeArea.id).toEqual(administrativeAreaInternalId);
  });
  it('should administrativeArea country to be accurate', async () => {
    const administrativeArea = await elLoadById(testContext, ADMIN_USER, 'location--861af688-581e-4571-a0d9-955c9096fb42');
    const queryResult = await editorQuery({
      query: READ_QUERY,
      variables: { id: administrativeArea.internal_id }, // f036de6b-10d9-4e85-a13f-0d013b2393e6
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.administrativeArea).not.toBeNull();
    expect(queryResult.data.administrativeArea.name).toEqual('Bretagne');
    expect(queryResult.data.administrativeArea.country.name).toEqual('France');
  });
  it('should list administrativeAreas', async () => {
    const queryResult = await editorQuery({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.administrativeAreas.edges.length).toEqual(2);
  });
  it('should update administrativeArea', async () => {
    const UPDATE_QUERY = gql`
        mutation AdministrativeAreaEdit($id: ID!, $input: [EditInput]!) {
            administrativeAreaFieldPatch(id: $id, input: $input) {
                id
                name
            }
        }
    `;
    const queryResult = await editorQuery({
      query: UPDATE_QUERY,
      variables: { id: administrativeAreaInternalId, input: { key: 'name', value: ['Administrative-Area - test'] } },
    });
    expect(queryResult.data.administrativeAreaFieldPatch.name).toEqual('Administrative-Area - test');
  });
  it('should context patch administrativeArea', async () => {
    const CONTEXT_PATCH_QUERY = gql`
        mutation AdministrativeAreaEdit($id: ID!, $input: EditContext!) {
            administrativeAreaContextPatch(id: $id,  input: $input) {
                id
            }
        }
    `;
    const queryResult = await editorQuery({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: administrativeAreaInternalId, input: { focusOn: 'description' } },
    });
    expect(queryResult.data.administrativeAreaContextPatch.id).toEqual(administrativeAreaInternalId);
  });
  it('should context clean administrativeArea', async () => {
    const CONTEXT_CLEAN_QUERY = gql`
        mutation AdministrativeAreaEdit($id: ID!) {
            administrativeAreaContextClean(id: $id) {
                id
            }
        }
    `;
    const queryResult = await editorQuery({
      query: CONTEXT_CLEAN_QUERY,
      variables: { id: administrativeAreaInternalId },
    });
    expect(queryResult.data.administrativeAreaContextClean.id).toEqual(administrativeAreaInternalId);
  });
  it('should add relation in administrativeArea', async () => {
    const RELATION_ADD_QUERY = gql`
          mutation AdministrativeAreaEdit($id: ID!, $input: StixRefRelationshipAddInput!) {
              administrativeAreaRelationAdd(id: $id, input: $input) {
                  id
                  from {
                      ... on AdministrativeArea {
                          objectMarking {
                              id
                          }
                      }
                  }
              }
          }
      `;
    const queryResult = await editorQuery({
      query: RELATION_ADD_QUERY,
      variables: {
        id: administrativeAreaInternalId,
        input: {
          toId: MARKING_TLP_GREEN,
          relationship_type: 'object-marking',
        },
      },
    });
    expect(queryResult.data.administrativeAreaRelationAdd.from.objectMarking.length).toEqual(1);
  });
  it('should delete relation in administrativeArea', async () => {
    const RELATION_DELETE_QUERY = gql`
            mutation AdministrativeAreaEdit($id: ID!, $toId: StixRef!, $relationship_type: String!) {
                administrativeAreaRelationDelete(id: $id, toId: $toId, relationship_type: $relationship_type) {
                    id
                    objectMarking {
                        id
                    }
                }
            }
        `;
    const queryResult = await editorQuery({
      query: RELATION_DELETE_QUERY,
      variables: {
        id: administrativeAreaInternalId,
        toId: MARKING_TLP_GREEN,
        relationship_type: 'object-marking',
      },
    });
    expect(queryResult.data.administrativeAreaRelationDelete.objectMarking.length).toEqual(0);
  });
  it('should administrativeArea deleted', async () => {
    const DELETE_QUERY = gql`
            mutation administrativeAreaDelete($id: ID!) {
                administrativeAreaDelete(id: $id)
            }
        `;
    // Delete the administrativeArea
    await editorQuery({
      query: DELETE_QUERY,
      variables: { id: administrativeAreaInternalId },
    });
    // Verify is no longer found
    const queryResult = await editorQuery({ query: READ_QUERY, variables: { id: administrativeAreaStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.administrativeArea).toBeNull();
  });
});
