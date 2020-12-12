import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';
import { elLoadByIds } from '../../../src/database/elasticSearch';

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
    xOpenCTIIncidents(
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
  ) {
    xOpenCTIIncidentsTimeSeries(
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
  query XOpenCTIIncident($id: String!) {
    xOpenCTIIncident(id: $id) {
      id
      standard_id
      name
      description
      toStix
    }
  }
`;

describe('XOpenCTIIncident resolver standard behavior', () => {
  let xOpenCTIIncidentInternalId;
  const xOpenCTIIncidentStixId = 'x-opencti-incident--1cbc610d-9f6b-4937-a404-2bec7f261ae5';
  it('should XOpenCTIIncident created', async () => {
    const CREATE_QUERY = gql`
      mutation XOpenCTIIncidentAdd($input: XOpenCTIIncidentAddInput) {
        xOpenCTIIncidentAdd(input: $input) {
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
    const xOpenCTIIncident = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: X_OPENCTI_INCIDENT_TO_CREATE,
    });
    expect(xOpenCTIIncident).not.toBeNull();
    expect(xOpenCTIIncident.data.xOpenCTIIncidentAdd).not.toBeNull();
    expect(xOpenCTIIncident.data.xOpenCTIIncidentAdd.name).toEqual('XOpenCTIIncident');
    xOpenCTIIncidentInternalId = xOpenCTIIncident.data.xOpenCTIIncidentAdd.id;
  });
  it('should XOpenCTIIncident loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: xOpenCTIIncidentInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.xOpenCTIIncident).not.toBeNull();
    expect(queryResult.data.xOpenCTIIncident.id).toEqual(xOpenCTIIncidentInternalId);
    expect(queryResult.data.xOpenCTIIncident.toStix.length).toBeGreaterThan(5);
  });
  it('should XOpenCTIIncident loaded by stix id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: xOpenCTIIncidentInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.xOpenCTIIncident).not.toBeNull();
    expect(queryResult.data.xOpenCTIIncident.id).toEqual(xOpenCTIIncidentInternalId);
  });
  it('should list XOpenCTIIncidents', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.xOpenCTIIncidents.edges.length).toEqual(2);
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
    expect(queryResult.data.xOpenCTIIncidentsTimeSeries.length).toEqual(13);
    expect(queryResult.data.xOpenCTIIncidentsTimeSeries[2].value).toEqual(1);
  });
  it("should timeseries of an entity's XOpenCTIIncidents", async () => {
    const campaign = await elLoadByIds('campaign--92d46985-17a6-4610-8be8-cc70c82ed214');
    const queryResult = await queryAsAdmin({
      query: TIMESERIES_QUERY,
      variables: {
        objectId: campaign.internal_id,
        field: 'first_seen',
        operation: 'count',
        startDate: '2020-01-01T00:00:00+00:00',
        endDate: '2021-01-01T00:00:00+00:00',
        interval: 'month',
        relationship_type: 'attributed-to',
      },
    });
    expect(queryResult.data.xOpenCTIIncidentsTimeSeries.length).toEqual(13);
    expect(queryResult.data.xOpenCTIIncidentsTimeSeries[1].value).toEqual(1);
  });
  it('should update XOpenCTIIncident', async () => {
    const UPDATE_QUERY = gql`
      mutation XOpenCTIIncidentEdit($id: ID!, $input: EditInput!) {
        xOpenCTIIncidentEdit(id: $id) {
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
    expect(queryResult.data.xOpenCTIIncidentEdit.fieldPatch.name).toEqual('XOpenCTIIncident - test');
  });
  it('should context patch XOpenCTIIncident', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation XOpenCTIIncidentEdit($id: ID!, $input: EditContext) {
        xOpenCTIIncidentEdit(id: $id) {
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
    expect(queryResult.data.xOpenCTIIncidentEdit.contextPatch.id).toEqual(xOpenCTIIncidentInternalId);
  });
  it('should context clean XOpenCTIIncident', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation XOpenCTIIncidentEdit($id: ID!) {
        xOpenCTIIncidentEdit(id: $id) {
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
    expect(queryResult.data.xOpenCTIIncidentEdit.contextClean.id).toEqual(xOpenCTIIncidentInternalId);
  });
  it('should add relation in XOpenCTIIncident', async () => {
    const RELATION_ADD_QUERY = gql`
      mutation XOpenCTIIncidentEdit($id: ID!, $input: StixMetaRelationshipAddInput!) {
        xOpenCTIIncidentEdit(id: $id) {
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
    expect(queryResult.data.xOpenCTIIncidentEdit.relationAdd.from.objectMarking.edges.length).toEqual(1);
  });
  it('should delete relation in XOpenCTIIncident', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation XOpenCTIIncidentEdit($id: ID!, $toId: String!, $relationship_type: String!) {
        xOpenCTIIncidentEdit(id: $id) {
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
    expect(queryResult.data.xOpenCTIIncidentEdit.relationDelete.objectMarking.edges.length).toEqual(0);
  });
  it('should XOpenCTIIncident deleted', async () => {
    const DELETE_QUERY = gql`
      mutation XOpenCTIIncidentDelete($id: ID!) {
        xOpenCTIIncidentEdit(id: $id) {
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
    expect(queryResult.data.xOpenCTIIncident).toBeNull();
  });
});
