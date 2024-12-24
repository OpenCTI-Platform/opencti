import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, getUserIdByEmail, queryAsAdmin, TEST_ORGANIZATION, testContext, USER_EDITOR } from '../../utils/testQuery';
import { findById } from '../../../src/modules/case/case-rfi/case-rfi-domain';
import { RELATION_OBJECT_ASSIGNEE, RELATION_OBJECT_PARTICIPANT } from '../../../src/schema/stixRefRelationship';
import { queryAsAdminWithSuccess } from '../../utils/testQueryHelper';
import { getOrganizationEntity } from '../../utils/domainQueryHelper';

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
    const testOrgEntity = await getOrganizationEntity(TEST_ORGANIZATION);
    const requestAccessData = await queryAsAdminWithSuccess({
      query: CREATE_QUERY,
      variables: {
        input: {
          request_access_reason: 'Access needed for project X',
          request_access_entities: [malware.data?.malwareAdd.id],
          request_access_members: [testOrgEntity.id],
          request_access_type: 'organization_sharing',
        },
      },
    });

    expect(requestAccessData).not.toBeNull();
    caseRfiId = requestAccessData?.data?.requestAccessAdd;
    expect(caseRfiId).not.toBeNull();
  });

  it('should retrieve the created Case RFI with correct participant and objects', async () => {
    const userEditorId = await getUserIdByEmail(USER_EDITOR.email);
    const queryResult = await queryAsAdminWithSuccess({
      query: READ_QUERY,
      variables: { id: caseRfiId },
    });
    const caseRequestForInformation = await findById(testContext, ADMIN_USER, caseRfiId);
    expect(queryResult?.data?.caseRfi).not.toBeNull();
    expect(queryResult?.data?.caseRfi.id).toEqual(caseRequestForInformation.id);
    expect(queryResult?.data?.caseRfi.name).toContain(caseRequestForInformation.name);
    expect(caseRequestForInformation[RELATION_OBJECT_PARTICIPANT]).toContain(ADMIN_USER.id);
    expect(caseRequestForInformation[RELATION_OBJECT_ASSIGNEE]).toContain(userEditorId);
    expect(caseRequestForInformation.object).toEqual([malware.data?.malwareAdd.id]);
  });
});
