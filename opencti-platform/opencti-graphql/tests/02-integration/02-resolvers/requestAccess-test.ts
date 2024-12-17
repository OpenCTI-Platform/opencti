import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, queryAsAdmin, TEST_ORGANIZATION } from '../../utils/testQuery';

const CREATE_QUERY = gql`
  mutation RequestAccessAdd($input: RequestAccessAddInput!) {
    requestAccessAdd(input: $input)
  }
`;

const CREATE_MALWARE_QUERY = gql`
  mutation MalwareAdd($input: MalwareAddInput!) {
    malwareAdd(input: $input) {
      id
      name
      description
    }
  }
`;

const READ_QUERY = gql`
  query caseRfi($id: String!) {
    caseRfi(id: $id) {
      id
      name
      objectParticipant {
        id
        name
      }
      objects {
        edges {
          node {
            ... on BasicObject {
              id
              entity_type
              standard_id
            }
            ... on BasicRelationship {
              id
              entity_type
              standard_id
            }
          }
        }
      }
    }
  }
`;

describe('Add Request Access to an entity and create an RFI', async () => {
  let caseRfiId: string;
  const malwareStixId = 'malware--34c9875d-8206-4f4b-bf17-f58d9cf7ebec';
  const MALWARE_TO_CREATE = {
    input: {
      name: 'Malware',
      stix_id: malwareStixId,
      description: 'Malware description',
    },
  };
  const malware = await queryAsAdmin({
    query: CREATE_MALWARE_QUERY,
    variables: MALWARE_TO_CREATE,
  });
  it('should create a Request Access and associated Case RFI', async () => {
    const requestAccessData = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: {
        input: {
          request_access_reason: 'Access needed for project X',
          request_access_entities: [malware.data?.malwareAdd.id],
          request_access_members: [TEST_ORGANIZATION.id],
          request_access_type: 'organization',
        },
      },
    });

    expect(requestAccessData).not.toBeNull();
    caseRfiId = requestAccessData?.data?.requestAccessAdd;
    expect(caseRfiId).not.toBeNull();
  });

  it('should retrieve the created Case RFI with correct participant and objects', async () => {
    const queryResult = await queryAsAdmin({
      query: READ_QUERY,
      variables: { id: caseRfiId },
    });
    const caseRfi = queryResult?.data?.caseRfi;
    console.log('caseRfi', caseRfi);
    expect(caseRfi).not.toBeNull();
    expect(caseRfi.id).toEqual(caseRfiId);
    expect(caseRfi.name).toContain(queryResult.data?.caseRfi.name);
    console.log('adminUser', ADMIN_USER);
    console.log('objectParticipant', caseRfi.objectParticipant);
    expect(caseRfi.objectParticipant).toContain(ADMIN_USER.id);
    expect(caseRfi.objects).toEqual([malware.data?.malwareAdd.id]);
  });
});
