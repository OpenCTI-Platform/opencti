import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';
import type { CaseIncident } from '../../../src/generated/graphql';

const CREATE_QUERY = gql`
  mutation CaseIncidentAdd($input: CaseIncidentAddInput!) {
    caseIncidentAdd(input: $input){
      id
      standard_id
      name
      description
    }
  }
`;

const READ_QUERY = gql`
  query caseIncident($id: String!) {
    caseIncident(id: $id) {
      id
      standard_id
      name
      description
    }
  }
`;

const LIST_QUERY = gql`
  query caseIncidents(
    $first: Int
    $after: ID
    $orderBy: CaseIncidentsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $search: String
    $toStix: Boolean
  ) {
    caseIncidents(
      first: $first
      after: $after
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
      search: $search
      toStix: $toStix
    ) {
      edges {
        node {
          id
          standard_id
        }
      }
    }
  }
`;

const DELETE_QUERY = gql`
  mutation CaseIncidentDelete($id: ID!) {
    caseIncidentDelete(id: $id)
  }
`;

describe('Case Incident Response resolver standard behavior', () => {
  let caseIncidentResponse: CaseIncident;
  it('should Case Incident Response created', async () => {
    const caseIncidentResponseData = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: {
        input: {
          name: 'Case Incident Response'
        }
      }
    });
    expect(caseIncidentResponseData).not.toBeNull();
    caseIncidentResponse = caseIncidentResponseData?.data?.caseIncidentAdd;
  });
  it('should Case Incident Response loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: caseIncidentResponse.id } });
    expect(queryResult).not.toBeNull();
    expect(queryResult?.data?.caseIncident).not.toBeNull();
    expect(queryResult?.data?.caseIncident.id).toEqual(caseIncidentResponse.id);
  });
  it('should Case Incident Response loaded by standard id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: caseIncidentResponse.standard_id } });
    expect(queryResult).not.toBeNull();
    expect(queryResult?.data?.caseIncident).not.toBeNull();
    expect(queryResult?.data?.caseIncident.id).toEqual(caseIncidentResponse.id);
  });
  it('should list Case Incident Response', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult?.data?.caseIncidents.edges.length).toEqual(1);
  });
  it('should update Case Incident Response', async () => {
    const UPDATE_QUERY = gql`
      mutation CaseIncident($id: ID!, $input: [EditInput]!) {
        stixDomainObjectEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            ... on Case {
              name
            }
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: caseIncidentResponse.id, input: { key: 'name', value: ['Case - updated'] } },
    });
    expect(queryResult?.data?.stixDomainObjectEdit.fieldPatch.name).toEqual('Case - updated');
  });
  it('should Case Incident Response deleted', async () => {
    // Delete the case
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: caseIncidentResponse.id },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: caseIncidentResponse.id } });
    expect(queryResult).not.toBeNull();
    expect(queryResult?.data?.caseIncident).toBeNull();
  });
});
