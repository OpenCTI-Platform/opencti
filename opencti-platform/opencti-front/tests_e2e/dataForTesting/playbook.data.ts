import { APIRequestContext } from '@playwright/test';
import { executeGraphql } from './query-utils';

export const THREAT_ADVISORY_PLAYBOOK_NAME = 'Threat Advisory Report access restrictions';

/** Deletes every playbook with this exact name (a running one is unregistered by the backend), so a re-run never stacks duplicates. */
export const deletePlaybooksByName = async (request: APIRequestContext, name: string) => {
  const { playbooks } = await executeGraphql<{ playbooks: { edges: { node: { id: string; name: string } }[] } }>(
    request,
    `List playbooks named ${name}`,
    'query FixturePlaybooks($search: String) { playbooks(search: $search) { edges { node { id name } } } }',
    { search: name },
  );
  const ids = playbooks.edges.map(({ node }) => node).filter((node) => node.name === name).map(({ id }) => id);
  for (const id of ids) {
    await executeGraphql(request, `Delete playbook ${name}`, 'mutation FixturePlaybookDelete($id: ID!) { playbookDelete(id: $id) }', { id });
  }
};
