import { afterEach, describe, expect, it, vi } from 'vitest';
import { createEntity } from '../../../../src/database/middleware';
import { notify } from '../../../../src/database/redis';
import { addDraftWorkspace } from '../../../../src/modules/draftWorkspace/draftWorkspace-domain';
import { addHuntProposal, assistHunt, planHunt } from '../../../../src/modules/hunt/hunt-domain';
import { callHuntAgent } from '../../../../src/modules/hunt/hunt-agents';
import { findByIds } from '../../../../src/modules/hunt/hunt-loaders';
import { RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../../../../src/schema/stixRefRelationship';
import type { BasicStoreEntity } from '../../../../src/types/store';
import { HuntStatus, HuntType } from '../../../../src/generated/graphql';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';

vi.mock('../../../../src/modules/hunt/hunt-loaders', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-loaders')>(),
  findByIds: vi.fn(),
}));

vi.mock('../../../../src/modules/draftWorkspace/draftWorkspace-domain', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/draftWorkspace/draftWorkspace-domain')>(),
  addDraftWorkspace: vi.fn(),
}));

vi.mock('../../../../src/database/middleware', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware')>(),
  createEntity: vi.fn(),
}));

vi.mock('../../../../src/database/redis', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/redis')>(),
  notify: vi.fn(),
}));

vi.mock('../../../../src/enterprise-edition/ee', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/enterprise-edition/ee')>(),
  checkEnterpriseEdition: vi.fn(async () => undefined),
}));

vi.mock('../../../../src/modules/hunt/hunt-agents', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-agents')>(),
  callHuntAgent: vi.fn(),
}));

const reference = (id: string, markings: string[], organizations: string[] = []) => ({
  internal_id: id,
  [RELATION_OBJECT_MARKING]: markings,
  [RELATION_GRANTED_TO]: organizations,
} as unknown as BasicStoreEntity);

const proposalInput = {
  name: 'Encoded PowerShell',
  hypothesis: 'The intrusion set runs encoded PowerShell on our hosts',
  hunt_type: HuntType.Telemetry,
  huntTargets: ['intrusion-set-1'],
  huntSources: ['report-1'],
};

describe('Hunt proposals of agents', () => {
  afterEach(() => {
    vi.mocked(findByIds).mockReset();
    vi.mocked(createEntity).mockReset();
    vi.mocked(addDraftWorkspace).mockReset();
  });

  const proposedMarkings = async (input: Record<string, unknown>) => {
    vi.mocked(addDraftWorkspace).mockResolvedValue({ id: 'draft-1' } as Awaited<ReturnType<typeof addDraftWorkspace>>);
    vi.mocked(createEntity).mockImplementation(async (_context, _user, created) => ({ ...created, internal_id: 'hunt-1' }));
    vi.mocked(notify).mockImplementation(async (_topic, element) => element);
    const proposal = await addHuntProposal(testContext, ADMIN_USER, { ...proposalInput, ...input });
    expect(proposal.draft_id).toEqual('draft-1');
    const [draftContext, , created] = vi.mocked(createEntity).mock.calls[0];
    expect(draftContext.draft_context).toEqual('draft-1');
    return created.objectMarking;
  };

  it('should carry the markings of the targets and sources it references on top of the requested ones', async () => {
    vi.mocked(findByIds).mockResolvedValue([reference('intrusion-set-1', ['tlp-amber']), reference('report-1', ['tlp-amber', 'pap-red'])]);
    expect(await proposedMarkings({ objectMarking: ['tlp-green'] })).toEqual(['tlp-green', 'tlp-amber', 'pap-red']);
    expect(vi.mocked(findByIds).mock.calls[0][2]).toEqual(['intrusion-set-1', 'report-1']);
  });

  it('should carry the markings and the organizations of the techniques it references', async () => {
    vi.mocked(findByIds).mockResolvedValue([
      reference('intrusion-set-1', [], ['org-a', 'org-b']),
      reference('report-1', [], ['org-a']),
      reference('attack-pattern-1', ['tlp-amber'], ['org-a']),
    ]);
    expect(await proposedMarkings({ huntTechniques: ['attack-pattern-1'] })).toEqual(['tlp-amber']);
    expect(vi.mocked(findByIds).mock.calls[0][2]).toEqual(['intrusion-set-1', 'report-1', 'attack-pattern-1']);
    expect(vi.mocked(createEntity).mock.calls[0][2].objectOrganization).toEqual(['org-a']);
    const [, , workspace] = vi.mocked(addDraftWorkspace).mock.calls[0];
    expect(JSON.stringify(workspace)).not.toContain(proposalInput.name);
  });

  it('should keep a proposal without references as requested and read nothing', async () => {
    expect(await proposedMarkings({ huntTargets: [], huntSources: [], objectMarking: ['tlp-green'] })).toEqual(['tlp-green']);
    expect(findByIds).not.toHaveBeenCalled();
  });

  it('should start as a draft hunt, whoever proposes it', async () => {
    vi.mocked(findByIds).mockResolvedValue([]);
    await proposedMarkings({ huntTargets: [], huntSources: [] });
    expect(vi.mocked(createEntity).mock.calls[0][2].hunt_status).toEqual('draft');
  });

  it('should start as a draft hunt even when the proposal asks for an active one', async () => {
    vi.mocked(findByIds).mockResolvedValue([]);
    await proposedMarkings({ huntTargets: [], huntSources: [], hunt_status: HuntStatus.Active });
    expect(vi.mocked(createEntity).mock.calls[0][2].hunt_status).toEqual('draft');
  });

  it('should keep the name and hypothesis of a restricted proposal out of its draft workspace', async () => {
    vi.mocked(findByIds).mockResolvedValue([reference('intrusion-set-1', ['tlp-red']), reference('report-1', [])]);
    await proposedMarkings({});
    const [, , workspace] = vi.mocked(addDraftWorkspace).mock.calls[0];
    expect(workspace.name).toMatch(/^Hunt proposal - /);
    expect(JSON.stringify(workspace)).not.toContain(proposalInput.name);
    expect(JSON.stringify(workspace)).not.toContain(proposalInput.hypothesis);
  });

  it('should name the draft workspace of an unrestricted proposal after the hunt', async () => {
    vi.mocked(findByIds).mockResolvedValue([reference('intrusion-set-1', []), reference('report-1', [])]);
    await proposedMarkings({});
    const [, , workspace] = vi.mocked(addDraftWorkspace).mock.calls[0];
    expect(workspace.name).toEqual(`Hunt proposal - ${proposalInput.name}`);
    expect(workspace.description).toContain(proposalInput.hypothesis);
    expect(workspace.authorized_members).toBeUndefined();
  });

  it('should share the proposal and its draft workspace only with the organizations its references all share', async () => {
    vi.mocked(findByIds).mockResolvedValue([reference('intrusion-set-1', [], ['org-a', 'org-b']), reference('report-1', [], ['org-b', 'org-c'])]);
    await proposedMarkings({});
    expect(vi.mocked(createEntity).mock.calls[0][2].objectOrganization).toEqual(['org-b']);
    const [, , workspace] = vi.mocked(addDraftWorkspace).mock.calls[0];
    expect(workspace.authorized_members).toEqual([{ id: ADMIN_USER.id, access_right: 'admin' }, { id: 'org-b', access_right: 'edit' }]);
    expect(workspace.name).toMatch(/^Hunt proposal - /);
    expect(JSON.stringify(workspace)).not.toContain(proposalInput.name);
  });

  it('should share with no organization a proposal referencing an object shared with none, whatever the caller asked for', async () => {
    vi.mocked(findByIds).mockResolvedValue([reference('intrusion-set-1', [], ['org-a']), reference('report-1', [])]);
    await proposedMarkings({ objectOrganization: ['org-a'] });
    expect(vi.mocked(createEntity).mock.calls[0][2].objectOrganization).toEqual([]);
  });

  it('should keep the organizations asked for that every reference shares', async () => {
    vi.mocked(findByIds).mockResolvedValue([reference('intrusion-set-1', [], ['org-a', 'org-b']), reference('report-1', [], ['org-a', 'org-b'])]);
    await proposedMarkings({ objectOrganization: ['org-b'] });
    expect(vi.mocked(createEntity).mock.calls[0][2].objectOrganization).toEqual(['org-b']);
  });

  it('should refuse a proposal whose references share no organization, creating nothing', async () => {
    vi.mocked(findByIds).mockResolvedValue([reference('intrusion-set-1', [], ['org-a']), reference('report-1', [], ['org-b'])]);
    await expect(addHuntProposal(testContext, ADMIN_USER, proposalInput)).rejects.toThrow(/organizations that have none in common/);
    expect(addDraftWorkspace).not.toHaveBeenCalled();
    expect(createEntity).not.toHaveBeenCalled();
  });

  it('should refuse a proposal restricted to organizations when its caller cannot restrict access to organizations', async () => {
    vi.mocked(findByIds).mockResolvedValue([reference('intrusion-set-1', [], ['org-a']), reference('report-1', [], ['org-a'])]);
    const caller = { ...ADMIN_USER, capabilities: [{ name: 'KNOWLEDGE_KNUPDATE' }] } as typeof ADMIN_USER;
    await expect(addHuntProposal(testContext, caller, proposalInput)).rejects.toThrow(/only a user who can restrict access to organizations/);
    expect(addDraftWorkspace).not.toHaveBeenCalled();
    expect(createEntity).not.toHaveBeenCalled();
  });

  const membersOnly = (id: string, entityType: string) => ({
    ...reference(id, []),
    entity_type: entityType,
    restricted_members: [{ id: 'user-analyst', access_right: 'view' }],
  } as unknown as BasicStoreEntity);

  it('should refuse a proposal referencing intelligence restricted to authorized members, creating nothing', async () => {
    vi.mocked(findByIds).mockResolvedValue([reference('intrusion-set-1', []), membersOnly('report-1', 'Report')]);
    await expect(addHuntProposal(testContext, ADMIN_USER, proposalInput)).rejects.toThrow(/restricted to authorized members, which a hunt cannot be/);
    expect(addDraftWorkspace).not.toHaveBeenCalled();
    expect(createEntity).not.toHaveBeenCalled();
  });

  it('should refuse to plan from intelligence restricted to authorized members before the agent reads it', async () => {
    vi.mocked(findByIds).mockResolvedValue([{ ...reference('intrusion-set-1', []), entity_type: 'Intrusion-Set' } as BasicStoreEntity, membersOnly('grouping-1', 'Grouping')]);
    await expect(planHunt(testContext, ADMIN_USER, { entity_ids: ['intrusion-set-1', 'grouping-1'] } as Parameters<typeof planHunt>[2]))
      .rejects.toThrow(/cannot be planned: the intelligence it is planned from is restricted to authorized members/);
    expect(callHuntAgent).not.toHaveBeenCalled();
    expect(addDraftWorkspace).not.toHaveBeenCalled();
    expect(createEntity).not.toHaveBeenCalled();
  });

  it('should refuse to write a hunt with XTM One from intelligence restricted to authorized members before the agent reads it', async () => {
    vi.mocked(findByIds).mockResolvedValue([{ ...reference('intrusion-set-1', []), entity_type: 'Intrusion-Set' } as BasicStoreEntity, membersOnly('grouping-1', 'Grouping')]);
    await expect(assistHunt(testContext, ADMIN_USER, { fields: [], target_ids: ['intrusion-set-1'], source_ids: ['grouping-1'] } as Parameters<typeof assistHunt>[2]))
      .rejects.toThrow(/cannot be written with XTM One: the intelligence it is written from is restricted to authorized members/);
    expect(callHuntAgent).not.toHaveBeenCalled();
  });
});
