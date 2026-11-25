import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  internalFindByIdsMapped: vi.fn(),
}));

import { internalFindByIdsMapped } from '../../../../src/database/middleware-loader';
import { importPlaybookUserReferences } from '../../../../src/modules/playbook/playbook-references';
import type { AuthContext } from '../../../../src/types/user';

const context = { source: 'test' } as AuthContext;
const JANE = { internal_id: '0f6d5b0a-4f4d-4a8b-9c1e-2f6a8d1c3b01', standard_id: 'user--6b1a3c0e-7f2d-5e4a-9b8c-1d2e3f4a5b6c' };
const MISSING = 'user--7c2b4d1f-8a3e-5f6b-0c9d-2e3f4a5b6c7d';
const GROUP_ID = '4d9a3b2f-6c7e-4f8a-9b0c-1d2e3f4a5b6c';

const definitionOf = (field: string, members: { label: string; value: string }[]) => ({
  nodes: [{ id: 'node', name: 'Restrict', position: { x: 0, y: 0 }, component_id: 'PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT', configuration: JSON.stringify({ [field]: members }) }],
  links: [],
});
const membersOf = (definition: { nodes: { configuration: string }[] }, field: string) => JSON.parse(definition.nodes[0].configuration)[field];

describe('Playbook user references of an import', () => {
  beforeEach(() => {
    vi.mocked(internalFindByIdsMapped).mockImplementation(async (_ctx, _user, ids) => {
      return Object.fromEntries((ids as string[]).filter((id) => id === JANE.standard_id).map((id) => [id, JANE])) as never;
    });
  });

  it('names the access restriction whose only member is a user the platform does not have', async () => {
    const result = await importPlaybookUserReferences(context, definitionOf('access_restrictions', [{ label: 'John', value: MISSING }]));
    expect(result.missing).toEqual(['John']);
    expect(membersOf(result.definition, 'access_restrictions')).toEqual([]);
    expect(result.emptiedAccessRestrictions).toEqual(['Restrict']);
  });

  it('keeps an access restriction that still has a member, with the internal id of the users it finds', async () => {
    const members = [{ label: 'John', value: MISSING }, { label: 'Jane', value: JANE.standard_id }, { label: 'Analysts', value: GROUP_ID }];
    const result = await importPlaybookUserReferences(context, definitionOf('access_restrictions', members));
    expect(membersOf(result.definition, 'access_restrictions')).toEqual([{ label: 'Jane', value: JANE.internal_id }, { label: 'Analysts', value: GROUP_ID }]);
    expect(result.emptiedAccessRestrictions).toEqual([]);
  });

  it('never names an access restriction that is already empty in the bundle', async () => {
    const result = await importPlaybookUserReferences(context, definitionOf('access_restrictions', []));
    expect(result.emptiedAccessRestrictions).toEqual([]);
  });

  it('only removes the missing recipients of the other member fields', async () => {
    const result = await importPlaybookUserReferences(context, definitionOf('authorized_members', [{ label: 'John', value: MISSING }]));
    expect(membersOf(result.definition, 'authorized_members')).toEqual([]);
    expect(result.emptiedAccessRestrictions).toEqual([]);
  });
});
