import gql from 'graphql-tag';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import * as ee from '../../../src/enterprise-edition/ee';
import { adminQuery } from '../../utils/testQuery';
import { awaitUntilCondition } from '../../utils/testQueryHelper';

describe.skip('Draft organization sharing', () => {
  beforeAll(() => {
    vi.spyOn(ee, 'isEnterpriseEdition').mockReturnValue(Promise.resolve(true));
    vi.spyOn(ee, 'checkEnterpriseEdition').mockReturnValue(Promise.resolve());
    vi.spyOn(ee, 'isEnterpriseEditionFromSettings').mockReturnValue(true);
  });

  afterAll(() => {
    vi.restoreAllMocks();
  });

  const MALWARE_QUERY = gql`
    query malware($id: String!) {
      malware(id: $id) {
        id
        name
        objectOrganization {
          id
          name
        }
      }
    }
  `;

  const MALWARE_ADD_QUERY = gql`
    mutation MalwareAdd($input: MalwareAddInput!) {
      malwareAdd(input: $input) {
        id
        name
      }
    }
  `;

  const DRAFT_WORKSPACE_ADD_QUERY = gql`
    mutation DraftWorkspaceAdd($input: DraftWorkspaceAddInput!) {
      draftWorkspaceAdd(input: $input) {
        id
        name
      }
    }
  `;

  const ORGANIZATION_ADD_QUERY = gql`
    mutation OrganizationAdd($input: OrganizationAddInput!) {
      organizationAdd(input: $input) {
        id
        name
      }
    }
  `;

  const RESTRICTION_ORGANIZATION_ADD_QUERY = gql`
    mutation restrictionOrganizationAdd($id: ID!, $organizationId: [ID!]!) {
      stixCoreObjectEdit(id: $id) {
        restrictionOrganizationAdd(organizationId: $organizationId) {
          id
          objectOrganization {
            id
            name
          }
        }
      }
    }
  `;

  const RESTRICTION_ORGANIZATION_DELETE_QUERY = gql`
    mutation restrictionOrganizationDelete($id: ID!, $organizationId: [ID!]!) {
      stixCoreObjectEdit(id: $id) {
        restrictionOrganizationDelete(organizationId: $organizationId) {
          id
          objectOrganization {
            id
            name
          }
        }
      }
    }
  `;

  const QUERY_TASK_ADD_QUERY = gql`
    mutation queryTaskAdd($input: QueryTaskAddInput!) {
      queryTaskAdd(input: $input) {
        id
        type
      }
    }
  `;

  const TASK_QUERY = gql`
    query backgroundTask($id: String!) {
      backgroundTask(id: $id) {
        id
        completed
      }
    }
  `;

  describe('Draft Organization Sharing', () => {
    it('should be able to share an entity with an organization in a draft', async () => {
      // 1. Setup: Create Organization and Malware in Live
      const orgRes = await adminQuery({
        query: ORGANIZATION_ADD_QUERY,
        variables: {
          input: {
            name: 'Draft Sharing Org',
            description: 'Used for testing organization sharing in drafts',
          },
        },
      });
      const orgId = orgRes.data.organizationAdd.id;

      const malwareRes = await adminQuery({
        query: MALWARE_ADD_QUERY,
        variables: {
          input: {
            name: 'Draft Sharing Malware',
          },
        },
      });
      const malwareId = malwareRes.data.malwareAdd.id;

      // 2. Create a Draft Workspace
      const draftRes = await adminQuery({
        query: DRAFT_WORKSPACE_ADD_QUERY,
        variables: {
          input: {
            name: 'Sharing Draft',
          },
        },
      });
      const draftId = draftRes.data.draftWorkspaceAdd.id;

      // 3. Share Malware with Org inside the Draft
      const shareRes = await adminQuery(
        {
          query: RESTRICTION_ORGANIZATION_ADD_QUERY,
          variables: {
            id: malwareId,
            organizationId: [orgId],
          },
        },
        { draftId },
      );

      expect(
        shareRes.data.stixCoreObjectEdit.restrictionOrganizationAdd.objectOrganization.length,
      ).toBe(1);

      // 4. Verify Malware in Draft has the organization
      const draftMalwareRes = await adminQuery(
        {
          query: MALWARE_QUERY,
          variables: { id: malwareId },
        },
        { draftId },
      );
      expect(draftMalwareRes.data.malware.objectOrganization.length).toBe(1);
      expect(draftMalwareRes.data.malware.objectOrganization[0].id).toBe(orgId);

      // 5. Verify Malware in Live STILL has NO organization
      const liveMalwareRes = await adminQuery({
        query: MALWARE_QUERY,
        variables: { id: malwareId },
      });
      expect(liveMalwareRes.data.malware.objectOrganization.length).toBe(0);

      // 6. Test Bulk Sharing via Task Manager in Draft
      // We use queryTaskAdd which creates a background task
      const taskRes = await adminQuery(
        {
          query: QUERY_TASK_ADD_QUERY,
          variables: {
            input: {
              filters: JSON.stringify({
                mode: 'and',
                filters: [{ key: ['internal_id'], values: [malwareId] }],
                filterGroups: [],
              }),
              actions: [
                {
                  type: 'SHARE',
                  context: {
                    values: [orgId],
                  },
                },
              ],
              scope: 'KNOWLEDGE',
            },
          },
        },
        { draftId },
      );
      expect(taskRes.data.queryTaskAdd).toBeDefined();
      expect(taskRes.errors).toBeUndefined();

      // Wait for task completion
      await awaitUntilCondition(
        async () => {
          const tRes = await adminQuery({
            query: TASK_QUERY,
            variables: { id: taskRes.data.queryTaskAdd.id },
          });
          return tRes.data.backgroundTask.completed;
        },
        1000,
        10000,
      );

      // 7. Test removing the restriction in Draft
      const unshareRes = await adminQuery(
        {
          query: RESTRICTION_ORGANIZATION_DELETE_QUERY,
          variables: {
            id: malwareId,
            organizationId: [orgId],
          },
        },
        { draftId },
      );
      expect(
        unshareRes.data.stixCoreObjectEdit.restrictionOrganizationDelete.objectOrganization.length,
      ).toBe(0);

      // Cleanup (in live)
      const DELETE_MALWARE = gql`
        mutation DeleteMalware($id: ID!) {
          stixCoreObjectEdit(id: $id) {
            delete
          }
        }
      `;
      await adminQuery({
        query: DELETE_MALWARE,
        variables: { id: malwareId },
      });

      const DELETE_ORG = gql`
        mutation DeleteOrg($id: ID!) {
          stixCoreObjectEdit(id: $id) {
            delete
          }
        }
      `;
      await adminQuery({
        query: DELETE_ORG,
        variables: { id: orgId },
      });

      const DELETE_DRAFT = gql`
        mutation DeleteDraft($id: ID!) {
          draftWorkspaceDelete(id: $id)
        }
      `;
      await adminQuery({
        query: DELETE_DRAFT,
        variables: { id: draftId },
      });
    });
  });
});
