/**
 * Undoes what the Threat Advisory setup specs leave on a long-lived local platform: the
 * "access restrictions" playbook (it rewrites authorized members on every Report creation), the
 * Draft workflow and OrgA's restricted visibility. Runs as the teardown of 'workflow setup',
 * i.e. after every project that depends on it.
 */
import { test } from '../fixtures/baseFixtures';
import { authenticateAdminApi } from '../dataForTesting/session.data';
import { deletePlaybooksByName, THREAT_ADVISORY_PLAYBOOK_NAME } from '../dataForTesting/playbook.data';
import { unrestrictOrganizationVisibility } from '../dataForTesting/organization.data';
import { executeGraphql } from '../dataForTesting/query-utils';

test('Tear down the Threat Advisory fixtures', { tag: ['@ee', '@workflow'] }, async ({ request }) => {
  await authenticateAdminApi(request);
  await deletePlaybooksByName(request, THREAT_ADVISORY_PLAYBOOK_NAME);
  await executeGraphql(
    request,
    'Reset the Draft workflow',
    'mutation FixtureResetWorkflow($entityType: String!) { workflowDefinitionDelete(entityType: $entityType) { id } }',
    { entityType: 'DraftWorkspace' },
  );
  await unrestrictOrganizationVisibility(request, 'OrgA');
});
