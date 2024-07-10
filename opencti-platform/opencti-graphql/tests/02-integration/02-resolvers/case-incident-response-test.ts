import { describe, it, expect } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';

describe('Case Incident Response resolver standard behavior', () => {
  let caseIncidentResponseId = '';

  const READ_QUERY = gql`
    query caseIncident($id: String!) {
      caseIncident(id: $id) {
        id
        standard_id
        name
        description
        toStix
        authorized_members {
          id
        }
      }
    }
`;

  it('should case incident response created', async () => {
    const CREATE_QUERY = gql`
      mutation CaseIncidentAdd($input: CaseIncidentAddInput!) {
        caseIncidentAdd(input: $input){
          id
          standard_id
          name
          description
          authorized_members {
            id
          }
        }
      }
    `;
    const caseIncidentResponseData = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: {
        input: {
          name: 'Case Incident Response'
        }
      }
    });
    expect(caseIncidentResponseData).not.toBeNull();
    expect(caseIncidentResponseData?.data?.caseIncidentAdd.authorized_members).not.toBeUndefined();
    caseIncidentResponseId = caseIncidentResponseData?.data?.caseIncidentAdd.id;
  });
  it('should Case Incident Response deleted', async () => {
    const DELETE_QUERY = gql`
      mutation CaseIncidentDelete($id: ID!) {
        caseIncidentDelete(id: $id)
      }
    `;
    // Delete the case
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: caseIncidentResponseId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: caseIncidentResponseId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult?.data?.caseIncident).toBeNull();
  });
});
