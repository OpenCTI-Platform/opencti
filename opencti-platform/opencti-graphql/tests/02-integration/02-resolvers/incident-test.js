import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';

const LIST_QUERY = gql`
  query incidents(
    $first: Int
    $after: ID
    $orderBy: IncidentsOrdering
    $orderMode: OrderingMode
    $filters: [IncidentsFiltering]
    $filterMode: FilterMode
    $search: String
  ) {
    incidents(
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

const TIMESERIES_QUERY = gql`
  query incidentsTimeSeries(
    $objectId: String
    $field: String!
    $operation: StatsOperation!
    $startDate: DateTime!
    $endDate: DateTime!
    $interval: String!
    $relationType: String
    $inferred: Boolean
  ) {
    incidentsTimeSeries(
      objectId: $objectId
      field: $field
      operation: $operation
      startDate: $startDate
      endDate: $endDate
      interval: $interval
      relationType: $relationType
      inferred: $inferred
    ) {
      date
      value
    }
  }
`;

const READ_QUERY = gql`
  query incident($id: String!) {
    incident(id: $id) {
      id
      name
      description
      observableRefs {
        edges {
          node {
            id
            observable_value
          }
        }
      }
      toStix
    }
  }
`;

describe('Incident resolver standard behavior', () => {
  let incidentInternalId;
  let incidentMarkingDefinitionRelationId;
  const incidentStixId = 'incident--1cbc610d-9f6b-4937-a404-2bec7f261ae5';
  it('should incident created', async () => {
    const CREATE_QUERY = gql`
      mutation IncidentAdd($input: IncidentAddInput) {
        incidentAdd(input: $input) {
          id
          name
          description
        }
      }
    `;
    // Create the incident
    const INCIDENT_TO_CREATE = {
      input: {
        name: 'Incident',
        stix_id_key: incidentStixId,
        description: 'Incident description',
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
    incidentInternalId = incident.data.incidentAdd.id;
  });
  it('should incident loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: incidentInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.incident).not.toBeNull();
    expect(queryResult.data.incident.id).toEqual(incidentInternalId);
    expect(queryResult.data.incident.toStix.length).toBeGreaterThan(5);
    expect(queryResult.data.incident.observableRefs.edges.length).toEqual(0);
  });
  it('should incident loaded by stix id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: incidentStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.incident).not.toBeNull();
    expect(queryResult.data.incident.id).toEqual(incidentInternalId);
  });
  it('should incident observable refs be accurate', async () => {
    const queryResult = await queryAsAdmin({
      query: READ_QUERY,
      variables: { id: '5e0a1dea-0f58-4da4-a00b-481640f8e7b3' },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.incident).not.toBeNull();
    expect(queryResult.data.incident.id).toEqual('5e0a1dea-0f58-4da4-a00b-481640f8e7b3');
    expect(queryResult.data.incident.observableRefs.edges.length).toEqual(1);
  });
  it('should list incidents', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.incidents.edges.length).toEqual(2);
  });
  it('should timeseries incidents', async () => {
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
  it("should timeseries of an entity's incidents", async () => {
    const queryResult = await queryAsAdmin({
      query: TIMESERIES_QUERY,
      variables: {
        objectId: 'fab6fa99-b07f-4278-86b4-b674edf60877',
        field: 'first_seen',
        operation: 'count',
        startDate: '2020-01-01T00:00:00+00:00',
        endDate: '2021-01-01T00:00:00+00:00',
        interval: 'month',
        relationType: 'attributed-to',
      },
    });
    expect(queryResult.data.incidentsTimeSeries.length).toEqual(13);
    expect(queryResult.data.incidentsTimeSeries[1].value).toEqual(1);
  });
  it('should update incident', async () => {
    const UPDATE_QUERY = gql`
      mutation IncidentEdit($id: ID!, $input: EditInput!) {
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
  it('should context patch incident', async () => {
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
  it('should context clean incident', async () => {
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
  it('should add relation in incident', async () => {
    const RELATION_ADD_QUERY = gql`
      mutation IncidentEdit($id: ID!, $input: RelationAddInput!) {
        incidentEdit(id: $id) {
          relationAdd(input: $input) {
            id
            from {
              ... on Incident {
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
        id: incidentInternalId,
        input: {
          fromRole: 'so',
          toRole: 'marking',
          toId: '43f586bc-bcbc-43d1-ab46-43e5ab1a2c46',
          through: 'object_marking_refs',
        },
      },
    });
    expect(queryResult.data.incidentEdit.relationAdd.from.markingDefinitions.edges.length).toEqual(1);
    incidentMarkingDefinitionRelationId =
      queryResult.data.incidentEdit.relationAdd.from.markingDefinitions.edges[0].relation.id;
  });
  it('should delete relation in incident', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation IncidentEdit($id: ID!, $relationId: ID!) {
        incidentEdit(id: $id) {
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
        id: incidentInternalId,
        relationId: incidentMarkingDefinitionRelationId,
      },
    });
    expect(queryResult.data.incidentEdit.relationDelete.markingDefinitions.edges.length).toEqual(0);
  });
  it('should incident deleted', async () => {
    const DELETE_QUERY = gql`
      mutation incidentDelete($id: ID!) {
        incidentEdit(id: $id) {
          delete
        }
      }
    `;
    // Delete the incident
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: incidentInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: incidentStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.incident).toBeNull();
  });
});
