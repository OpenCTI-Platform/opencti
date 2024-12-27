import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, getUserIdByEmail, TEST_ORGANIZATION, testContext, USER_EDITOR } from '../../utils/testQuery';
import { findById as findRFIById } from '../../../src/modules/case/case-rfi/case-rfi-domain';
import { RELATION_OBJECT_ASSIGNEE, RELATION_OBJECT_PARTICIPANT } from '../../../src/schema/stixRefRelationship';
import { queryAsAdminWithSuccess, queryAsUser } from '../../utils/testQueryHelper';
import { getOrganizationEntity } from '../../utils/domainQueryHelper';
import { internalDeleteElementById } from '../../../src/database/middleware';

export const CREATE_REQUEST_ACCESS_QUERY = gql`
    mutation RequestAccessAdd($input: RequestAccessAddInput!) {
        requestAccessAdd(input: $input)
    }
`;

export const CREATE_MALWARE_QUERY = gql`
    mutation MalwareAdd($input: MalwareAddInput!) {
        malwareAdd(input: $input) {
            id
            name
            description
        }
    }
`;

export const READ_RFI_QUERY = gql`
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

export const VALIDATE_RFI_QUERY = gql`
mutation ValidateRequestAccess($id: ID!) {
    requestAccessValidate(id: $id)
}`;

describe('Add Request Access to an entity and create an RFI', async () => {
  let caseRfiId: string;
  let malwareId: string;
  let testOrgId: string;
  it('should create malware with restricted access', async () => {
    const malwareStixId = 'malware--34c9875d-8206-4f4b-bf17-f58d9cf7ebec';
    const MALWARE_TO_CREATE = {
      input: {
        name: 'Malware',
        stix_id: malwareStixId,
        description: 'Malware description',
      },
    };
    const malware = await queryAsAdminWithSuccess({
      query: CREATE_MALWARE_QUERY,
      variables: MALWARE_TO_CREATE,
    });
    malwareId = malware.data?.malwareAdd.id;
    expect(malware.data?.malwareAdd.id).toBeDefined();

    const testOrgEntity = await getOrganizationEntity(TEST_ORGANIZATION);
    testOrgId = testOrgEntity.id;
  });
  it('should create a Request Access and associated Case RFI', async () => {
    const requestAccessData = await queryAsAdminWithSuccess({
      query: CREATE_REQUEST_ACCESS_QUERY,
      variables: {
        input: {
          request_access_reason: 'Access needed for project X',
          request_access_entities: [malwareId],
          request_access_members: [testOrgId],
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
      query: READ_RFI_QUERY,
      variables: { id: caseRfiId },
    });
    const caseRequestForInformation = await findRFIById(testContext, ADMIN_USER, caseRfiId);
    expect(queryResult?.data?.caseRfi).not.toBeNull();
    expect(queryResult?.data?.caseRfi.id).toEqual(caseRequestForInformation.id);
    expect(queryResult?.data?.caseRfi.name).toContain(caseRequestForInformation.name);
    expect(caseRequestForInformation[RELATION_OBJECT_PARTICIPANT]).toContain(ADMIN_USER.id);
    expect(caseRequestForInformation[RELATION_OBJECT_ASSIGNEE]).toContain(userEditorId);
    expect(caseRequestForInformation.object).toEqual([malwareId]);
  });

  it.skip('should accept the created Case RFI first time be ok', async () => {
    // FIXME why ?? it's forbidden XD
    const queryResult = await queryAsUser(USER_EDITOR.client, {
      query: VALIDATE_RFI_QUERY,
      variables: { id: caseRfiId },
    });
    expect(queryResult?.data?.caseRfi).not.toBeNull();
  });

  it('should delete malware and RFI created by test', async () => {
    await internalDeleteElementById(testContext, ADMIN_USER, malwareId);
    await internalDeleteElementById(testContext, ADMIN_USER, caseRfiId);
  });
});
