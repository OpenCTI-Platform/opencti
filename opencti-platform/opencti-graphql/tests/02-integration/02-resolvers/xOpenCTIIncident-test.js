import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';

const LIST_QUERY = gql`
  query XOpenCTIIncidents(
    $first: Int
    $after: ID
    $orderBy: XOpenCTIIncidentsOrdering
    $orderMode: OrderingMode
    $filters: [XOpenCTIIncidentsFiltering]
    $filterMode: FilterMode
    $search: String
  ) {
    XOpenCTIIncidents(
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
  query XOpenCTIIncidentsTimeSeries(
    $objectId: String
    $field: String!
    $operation: StatsOperation!
    $startDate: DateTime!
    $endDate: DateTime!
    $interval: String!
    $relationship_type: String
    $inferred: Boolean
  ) {
    XOpenCTIIncidentsTimeSeries(
      objectId: $objectId
      field: $field
      operation: $operation
      startDate: $startDate
      endDate: $endDate
      interval: $interval
      relationship_type: $relationship_type
      inferred: $inferred
    ) {
      date
      value
    }
  }
`;

const READ_QUERY = gql`
  query XOpenCTIIncident($id: String!) {
    XOpenCTIIncident(id: $id) {
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

describe('XOpenCTIIncident resolver standard behavior', () => {
  let xOpenCTIIncidentInternalId;
  const xOpenCTIIncidentStixId = 'XOpenCTIIncident--1cbc610d-9f6b-4937-a404-2bec7f261ae5';
  it('should XOpenCTIIncident created', async () => {
    const CREATE_QUERY = gql`
      mutation XOpenCTIIncidentAdd($input: XOpenCTIIncidentAddInput) {
        XOpenCTIIncidentAdd(input: $input) {
          id
          name
          description
        }
      }
    `;
    // Create the XOpenCTIIncident
    const X_OPENCTI_INCIDENT_TO_CREATE = {
      input: {
        name: 'XOpenCTIIncident',
        stix_id: xOpenCTIIncidentStixId,
        description: 'XOpenCTIIncident description',
        first_seen: '2020-03-24T10:51:20+00:00',
        last_seen: '2020-03-24T10:51:20+00:00',
      },
    };
    const XOpenCTIIncident = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: X_OPENCTI_INCIDENT_TO_CREATE,
    });
    expect(XOpenCTIIncident).not.toBeNull();
    expect(XOpenCTIIncident.data.XOpenCTIIncidentAdd).not.toBeNull();
    expect(XOpenCTIIncident.data.XOpenCTIIncidentAdd.name).toEqual('XOpenCTIIncident');
    xOpenCTIIncidentInternalId = XOpenCTIIncident.data.XOpenCTIIncidentAdd.id;
  });
  it('should XOpenCTIIncident loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: xOpenCTIIncidentInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.XOpenCTIIncident).not.toBeNull();
    expect(queryResult.data.XOpenCTIIncident.id).toEqual(xOpenCTIIncidentInternalId);
    expect(queryResult.data.XOpenCTIIncident.toStix.length).toBeGreaterThan(5);
    expect(queryResult.data.XOpenCTIIncident.observableRefs.edges.length).toEqual(0);
  });
  it('should XOpenCTIIncident loaded by stix id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: xOpenCTIIncidentInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.XOpenCTIIncident).not.toBeNull();
    expect(queryResult.data.XOpenCTIIncident.id).toEqual(xOpenCTIIncidentInternalId);
  });
  it('should XOpenCTIIncident observable refs be accurate', async () => {
    const queryResult = await queryAsAdmin({
      query: READ_QUERY,
      variables: { id: '5e0a1dea-0f58-4da4-a00b-481640f8e7b3' },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.XOpenCTIIncident).not.toBeNull();
    expect(queryResult.data.XOpenCTIIncident.id).toEqual('5e0a1dea-0f58-4da4-a00b-481640f8e7b3');
    expect(queryResult.data.XOpenCTIIncident.observableRefs.edges.length).toEqual(1);
  });
  it('should list XOpenCTIIncidents', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.XOpenCTIIncidents.edges.length).toEqual(2);
  });
  it('should timeseries XOpenCTIIncidents', async () => {
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
    expect(queryResult.data.XOpenCTIIncidentsTimeSeries.length).toEqual(13);
    expect(queryResult.data.XOpenCTIIncidentsTimeSeries[2].value).toEqual(1);
  });
  it("should timeseries of an entity's XOpenCTIIncidents", async () => {
    const queryResult = await queryAsAdmin({
      query: TIMESERIES_QUERY,
      variables: {
        objectId: 'fab6fa99-b07f-4278-86b4-b674edf60877',
        field: 'first_seen',
        operation: 'count',
        startDate: '2020-01-01T00:00:00+00:00',
        endDate: '2021-01-01T00:00:00+00:00',
        interval: 'month',
        relationship_type: 'attributed-to',
      },
    });
    expect(queryResult.data.XOpenCTIIncidentsTimeSeries.length).toEqual(13);
    expect(queryResult.data.XOpenCTIIncidentsTimeSeries[1].value).toEqual(1);
  });
  it('should update XOpenCTIIncident', async () => {
    const UPDATE_QUERY = gql`
      mutation XOpenCTIIncidentEdit($id: ID!, $input: EditInput!) {
        XOpenCTIIncidentEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            name
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: xOpenCTIIncidentInternalId, input: { key: 'name', value: ['XOpenCTIIncident - test'] } },
    });
    expect(queryResult.data.XOpenCTIIncidentEdit.fieldPatch.name).toEqual('XOpenCTIIncident - test');
  });
  it('should context patch XOpenCTIIncident', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation XOpenCTIIncidentEdit($id: ID!, $input: EditContext) {
        XOpenCTIIncidentEdit(id: $id) {
          contextPatch(input: $input) {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: xOpenCTIIncidentInternalId, input: { focusOn: 'description' } },
    });
    expect(queryResult.data.XOpenCTIIncidentEdit.contextPatch.id).toEqual(xOpenCTIIncidentInternalId);
  });
  it('should context clean XOpenCTIIncident', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation XOpenCTIIncidentEdit($id: ID!) {
        XOpenCTIIncidentEdit(id: $id) {
          contextClean {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: xOpenCTIIncidentInternalId },
    });
    expect(queryResult.data.XOpenCTIIncidentEdit.contextClean.id).toEqual(xOpenCTIIncidentInternalId);
  });
  it('should add relation in XOpenCTIIncident', async () => {
    const RELATION_ADD_QUERY = gql`
      mutation XOpenCTIIncidentEdit($id: ID!, $input: StixMetaRelationshipAddInput!) {
        XOpenCTIIncidentEdit(id: $id) {
          relationAdd(input: $input) {
            id
            from {
              ... on XOpenCTIIncident {
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
        id: xOpenCTIIncidentInternalId,
        input: {
          toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
          relationship_type: 'object-marking',
        },
      },
    });
    expect(queryResult.data.XOpenCTIIncidentEdit.relationAdd.from.objectMarking.edges.length).toEqual(1);
  });
  it('should delete relation in XOpenCTIIncident', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation XOpenCTIIncidentEdit($id: ID!, $toId: String!, $relationship_type: String!) {
        XOpenCTIIncidentEdit(id: $id) {
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
        id: xOpenCTIIncidentInternalId,
        toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
        relationship_type: 'object-marking',
      },
    });
    expect(queryResult.data.XOpenCTIIncidentEdit.relationDelete.objectMarking.edges.length).toEqual(0);
  });
  it('should XOpenCTIIncident deleted', async () => {
    const DELETE_QUERY = gql`
      mutation XOpenCTIIncidentDelete($id: ID!) {
        XOpenCTIIncidentEdit(id: $id) {
          delete
        }
      }
    `;
    // Delete the XOpenCTIIncident
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: xOpenCTIIncidentInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: xOpenCTIIncidentInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.XOpenCTIIncident).toBeNull();
  });
});
