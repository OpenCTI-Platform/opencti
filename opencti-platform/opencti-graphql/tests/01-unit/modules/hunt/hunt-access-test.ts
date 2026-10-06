import { afterEach, describe, expect, it, vi } from 'vitest';
import '../../../../src/modules/index';
import { storeLoadById } from '../../../../src/database/middleware-loader';
import { schemaAttributesDefinition } from '../../../../src/schema/schema-attributes';
import { authorizedMembers } from '../../../../src/schema/attribute-definition';
import { AUTHORIZED_MEMBERS_SUPPORTED_ENTITY_TYPES } from '../../../../src/utils/authorizedMembers';
import { checkHuntEditAccess, filterEditableHunts } from '../../../../src/modules/hunt/hunt-access';
import { retryHuntRun, setHuntRunVerdict, startHuntPreview, startHuntRuns } from '../../../../src/modules/hunt/huntRun/huntRun-domain';
import { ENTITY_TYPE_HUNT, type BasicStoreEntityHunt } from '../../../../src/modules/hunt/hunt-types';
import { ENTITY_TYPE_HUNT_RUN } from '../../../../src/modules/hunt/huntRun/huntRun-types';
import { ENTITY_TYPE_DRAFT_WORKSPACE } from '../../../../src/modules/draftWorkspace/draftWorkspace-types';
import type { AuthContext, AuthUser } from '../../../../src/types/user';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware-loader')>(),
  storeLoadById: vi.fn(),
}));

// Runs inherit the markings and organizations of their hunt only: restricting hunts to members would need their runs
// to apply that restriction on every read and every action first
describe('Hunt access', () => {
  it('should not let a hunt or a hunt run be restricted to members', () => {
    expect(AUTHORIZED_MEMBERS_SUPPORTED_ENTITY_TYPES).not.toContain(ENTITY_TYPE_HUNT);
    expect(AUTHORIZED_MEMBERS_SUPPORTED_ENTITY_TYPES).not.toContain(ENTITY_TYPE_HUNT_RUN);
    expect(schemaAttributesDefinition.getAttribute(ENTITY_TYPE_HUNT, authorizedMembers.name)).toBeUndefined();
    expect(schemaAttributesDefinition.getAttribute(ENTITY_TYPE_HUNT_RUN, authorizedMembers.name)).toBeUndefined();
  });
});

const READ_ONLY = 'You can read this hunt but not change it or its runs';

const analyst = {
  id: 'analyst-1',
  internal_id: 'analyst-1',
  capabilities: [{ name: 'KNOWLEDGE_KNUPDATE' }],
  groups: [{ internal_id: 'group-analysts' }],
  organizations: [],
  roles: [],
} as unknown as AuthUser;

const hunt = { internal_id: 'hunt-1', entity_type: ENTITY_TYPE_HUNT, name: 'DNS tunnelling', hunt_type: 'telemetry', hunt_status: 'active' } as unknown as BasicStoreEntityHunt;
const completedRun = { internal_id: 'run-1', entity_type: ENTITY_TYPE_HUNT_RUN, hunt_id: 'hunt-1', hunt_run_status: 'completed', hunt_run_mode: 'execute', verdict: 'pending' };
const inDraft = { ...testContext, draft_context: 'draft-1' } as AuthContext;

// The runs of a hunt are written by the hunt manager: the access of the user to the draft is checked before they are
const loadInDraft = (draftAccess: 'view' | 'edit', run: Record<string, unknown> = completedRun) => {
  const draft = { internal_id: 'draft-1', entity_type: ENTITY_TYPE_DRAFT_WORKSPACE, restricted_members: [{ id: 'group-analysts', access_right: draftAccess }] };
  const byType: Record<string, unknown> = { [ENTITY_TYPE_DRAFT_WORKSPACE]: draft, [ENTITY_TYPE_HUNT]: hunt, [ENTITY_TYPE_HUNT_RUN]: run };
  vi.mocked(storeLoadById).mockImplementation(async (_context, _user, _id, type) => byType[type as string] as never);
};

describe('Edit access to the hunt of a run', () => {
  afterEach(() => vi.mocked(storeLoadById).mockReset());

  it('should let a user change a hunt outside a draft, and in a draft only with the edit access to the draft', async () => {
    await expect(checkHuntEditAccess(testContext, analyst, hunt)).resolves.toBeUndefined();
    loadInDraft('edit');
    await expect(checkHuntEditAccess(inDraft, analyst, hunt)).resolves.toBeUndefined();
    loadInDraft('view');
    await expect(checkHuntEditAccess(inDraft, analyst, hunt)).rejects.toThrow(READ_ONLY);
    expect(await filterEditableHunts(inDraft, analyst, [hunt])).toEqual([]);
    expect(await filterEditableHunts(inDraft, ADMIN_USER, [hunt])).toEqual([hunt]);
  });

  it('should refuse to run, preview, retry or give a verdict to the runs of a hunt in a draft the user can only view', async () => {
    loadInDraft('view');
    await expect(startHuntRuns(inDraft, analyst, 'hunt-1', {})).rejects.toThrow(READ_ONLY);
    await expect(startHuntPreview(inDraft, analyst, 'hunt-1')).rejects.toThrow(READ_ONLY);
    await expect(setHuntRunVerdict(inDraft, analyst, 'run-1', { verdict: 'benign' } as never)).rejects.toThrow(READ_ONLY);
    loadInDraft('view', { ...completedRun, hunt_run_status: 'failed' });
    await expect(retryHuntRun(inDraft, analyst, 'run-1')).rejects.toThrow(READ_ONLY);
  });
});
