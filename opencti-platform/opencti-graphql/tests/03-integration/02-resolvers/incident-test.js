import { expect, it, describe } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { queryAsAdmin } from '../../utils/testQueryHelper';
import { elLoadById } from '../../../src/database/engine';

const LIST_QUERY = gql`
  query Incidents(
    $first: Int
    $after: ID
    $orderBy: IncidentsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $search: String
  ) {
    incidents(
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
          x_opencti_score
        }
      }
    }
  }
`;

const TIMESERIES_QUERY = gql`
  query IncidentsTimeSeries(
    $objectId: String
    $field: String!
    $operation: StatsOperation!
    $startDate: DateTime!
    $endDate: DateTime!
    $interval: String!
    $relationship_type: [String]
  ) {
    incidentsTimeSeries(
      objectId: $objectId
      field: $field
      operation: $operation
      startDate: $startDate
      endDate: $endDate
      interval: $interval
      relationship_type: $relationship_type
    ) {
      date
      value
    }
  }
`;

const READ_QUERY = gql`
  query Incident($id: String!) {
    incident(id: $id) {
      id
      standard_id
      name
      description
      x_opencti_score
      toStix
    }
  }
`;

const READ_SCORE_QUERY = gql`
  query IncidentScore($id: String!) {
    incident(id: $id) {
      id
      x_opencti_score
    }
  }
`;

describe('Incident resolver standard behavior', () => {
  let incidentInternalId;
  const incidentStixId = 'incident--1cbc610d-9f6b-4937-a404-2bec7f261ae5';
  it('should Incident created', async () => {
    const CREATE_QUERY = gql`
      mutation IncidentAdd($input: IncidentAddInput!) {
        incidentAdd(input: $input) {
          id
          name
          description
          x_opencti_score
        }
      }
    `;
    // Create the Incident
    const INCIDENT_TO_CREATE = {
      input: {
        name: 'Incident',
        stix_id: incidentStixId,
        description: 'Incident description',
        x_opencti_score: 42,
        first_seen: '2020-03-24T10:51:20+00:00',
        last_seen: '2020-03-24T10:51:20+00:00',
      },
    };
    const incident = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: INCIDENT_TO_CREATE,
    });
    expect(incident).not.toBeNull();
    expect(incident.data.incidentAdd).not.toBeNull();
    expect(incident.data.incidentAdd.name).toEqual('Incident');
    expect(incident.data.incidentAdd.x_opencti_score).toEqual(42);
    incidentInternalId = incident.data.incidentAdd.id;
  });
  it('should read Incident score value', async () => {
    const queryResult = await queryAsAdmin({ query: READ_SCORE_QUERY, variables: { id: incidentInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.incident).not.toBeNull();
    expect(queryResult.data.incident.x_opencti_score).toEqual(42);
  });
  it('should reject Incident creation with score below 0', async () => {
    const CREATE_QUERY = gql`
      mutation IncidentAdd($input: IncidentAddInput!) {
        incidentAdd(input: $input) {
          id
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: {
        input: {
          name: 'Incident invalid score -1',
          x_opencti_score: -1,
        },
      },
    });
    expect(queryResult.errors?.length).toBe(1);
    expect(queryResult.data?.incidentAdd).toBeNull();
  });
  it('should reject Incident creation with score above 100', async () => {
    const CREATE_QUERY = gql`
      mutation IncidentAdd($input: IncidentAddInput!) {
        incidentAdd(input: $input) {
          id
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: {
        input: {
          name: 'Incident invalid score 101',
          x_opencti_score: 101,
        },
      },
    });
    expect(queryResult.errors?.length).toBe(1);
    expect(queryResult.data?.incidentAdd).toBeNull();
  });
  it('should reject Incident creation with non integer score', async () => {
    const CREATE_QUERY = gql`
      mutation IncidentAdd($input: IncidentAddInput!) {
        incidentAdd(input: $input) {
          id
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: {
        input: {
          name: 'Incident invalid score 12.5',
          x_opencti_score: 12.5,
        },
      },
    });
    expect(queryResult.errors?.length).toBe(1);
    expect([null, undefined]).toContain(queryResult.data?.incidentAdd);
  });
  it('should reject Incident score field patch with non integer value', async () => {
    const UPDATE_SCORE_QUERY = gql`
      mutation IncidentEdit($id: ID!, $input: [EditInput]!) {
        incidentEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            x_opencti_score
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_SCORE_QUERY,
      variables: { id: incidentInternalId, input: { key: 'x_opencti_score', value: [12.5] } },
    });
    expect(queryResult.errors?.length).toBe(1);
    expect([null, undefined]).toContain(queryResult.data?.incidentEdit?.fieldPatch);
  });
  it('should Incident loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: incidentInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.incident).not.toBeNull();
    expect(queryResult.data.incident.id).toEqual(incidentInternalId);
    expect(queryResult.data.incident.toStix.length).toBeGreaterThan(5);
  });
  it('should Incident loaded by stix id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: incidentInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.incident).not.toBeNull();
    expect(queryResult.data.incident.id).toEqual(incidentInternalId);
  });
  it('should list Incidents', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.incidents.edges.length).toEqual(2);
  });
  it('should timeseries Incidents', async () => {
    const queryResult = await queryAsAdmin({
      query: TIMESERIES_QUERY,
      variables: {
        field: 'first_seen',
        operation: 'count',
        startDate: '2020-01-01T00:00:00+00:00',
        endDate: '2021-01-01T00:00:00+00:00',
        interval: 'month',
      },
    });
    expect(queryResult.data.incidentsTimeSeries.length).toEqual(13);
    expect(queryResult.data.incidentsTimeSeries[2].value).toEqual(1);
  });
  it("should timeseries of an entity's Incidents", async () => {
    const campaign = await elLoadById(testContext, ADMIN_USER, 'campaign--92d46985-17a6-4610-8be8-cc70c82ed214');
    const queryResult = await queryAsAdmin({
      query: TIMESERIES_QUERY,
      variables: {
        objectId: campaign.internal_id,
        field: 'first_seen',
        operation: 'count',
        startDate: '2020-01-01T00:00:00+00:00',
        endDate: '2021-01-01T00:00:00+00:00',
        interval: 'month',
        relationship_type: ['attributed-to'],
      },
    });
    expect(queryResult.data.incidentsTimeSeries.length).toEqual(13);
    expect(queryResult.data.incidentsTimeSeries[1].value).toEqual(1);
  });
  it('should update Incident', async () => {
    const UPDATE_QUERY = gql`
      mutation IncidentEdit($id: ID!, $input: [EditInput]!) {
        incidentEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            name
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: incidentInternalId, input: { key: 'name', value: ['Incident - test'] } },
    });
    expect(queryResult.data.incidentEdit.fieldPatch.name).toEqual('Incident - test');
  });
  it('should update Incident score using field patch', async () => {
    const UPDATE_SCORE_QUERY = gql`
      mutation IncidentEdit($id: ID!, $input: [EditInput]!) {
        incidentEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            x_opencti_score
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_SCORE_QUERY,
      variables: { id: incidentInternalId, input: { key: 'x_opencti_score', value: [73] } },
    });
    expect(queryResult.data.incidentEdit.fieldPatch.x_opencti_score).toEqual(73);

    const readResult = await queryAsAdmin({ query: READ_SCORE_QUERY, variables: { id: incidentInternalId } });
    expect(readResult.data.incident.x_opencti_score).toEqual(73);
  });
  it('should list Incidents ordered by score', async () => {
    const queryResult = await queryAsAdmin({
      query: LIST_QUERY,
      variables: {
        first: 10,
        orderBy: 'x_opencti_score',
        orderMode: 'desc',
        filters: {
          mode: 'and',
          filters: [{ key: ['name'], values: ['Incident - test'], operator: 'eq', mode: 'or' }],
          filterGroups: [],
        },
      },
    });
    expect(queryResult.data.incidents.edges.length).toBeGreaterThan(0);
    expect(queryResult.data.incidents.edges[0].node.x_opencti_score).toEqual(73);
  });
  it('should filter Incidents by score', async () => {
    const queryResult = await queryAsAdmin({
      query: LIST_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'and',
          filters: [{ key: ['x_opencti_score'], values: ['73'], operator: 'eq', mode: 'or' }],
          filterGroups: [],
        },
      },
    });
    const incidentIds = queryResult.data.incidents.edges.map((edge) => edge.node.id);
    expect(incidentIds).toContain(incidentInternalId);
  });
  it('should context patch Incident', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation IncidentEdit($id: ID!, $input: EditContext) {
        incidentEdit(id: $id) {
          contextPatch(input: $input) {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: incidentInternalId, input: { focusOn: 'description' } },
    });
    expect(queryResult.data.incidentEdit.contextPatch.id).toEqual(incidentInternalId);
  });
  it('should context clean Incident', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation IncidentEdit($id: ID!) {
        incidentEdit(id: $id) {
          contextClean {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: incidentInternalId },
    });
    expect(queryResult.data.incidentEdit.contextClean.id).toEqual(incidentInternalId);
  });
  it('should add relation in Incident', async () => {
    const RELATION_ADD_QUERY = gql`
      mutation IncidentEdit($id: ID!, $input: StixRefRelationshipAddInput!) {
        incidentEdit(id: $id) {
          relationAdd(input: $input) {
            id
            from {
              ... on Incident {
                objectMarking {
                  id
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
        id: incidentInternalId,
        input: {
          toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
          relationship_type: 'object-marking',
        },
      },
    });
    expect(queryResult.data.incidentEdit.relationAdd.from.objectMarking.length).toEqual(1);
  });
  it('should delete relation in Incident', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation IncidentEdit($id: ID!, $toId: StixRef!, $relationship_type: String!) {
        incidentEdit(id: $id) {
          relationDelete(toId: $toId, relationship_type: $relationship_type) {
            id
            objectMarking {
              id
            }
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: RELATION_DELETE_QUERY,
      variables: {
        id: incidentInternalId,
        toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
        relationship_type: 'object-marking',
      },
    });
    expect(queryResult.data.incidentEdit.relationDelete.objectMarking.length).toEqual(0);
  });
  it('should Incident deleted', async () => {
    const DELETE_QUERY = gql`
      mutation IncidentDelete($id: ID!) {
        incidentEdit(id: $id) {
          delete
        }
      }
    `;
    // Delete the Incident
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: incidentInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: incidentInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.incident).toBeNull();
  });
});
