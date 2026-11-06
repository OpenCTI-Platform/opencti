import { beforeEach, describe, expect, it, vi } from 'vitest';
import { addKillChainPhase } from '../../../src/domain/killChainPhase';
import { storeLoadById } from '../../../src/database/middleware-loader';
import { createEntity } from '../../../src/database/middleware';
import { generateStandardId } from '../../../src/schema/identifier';
import { ENTITY_TYPE_KILL_CHAIN_PHASE } from '../../../src/schema/stixMetaObject';

vi.mock('../../../src/database/middleware-loader', () => ({ storeLoadById: vi.fn(), pageEntitiesConnection: vi.fn() }));
vi.mock('../../../src/database/middleware', () => ({ createEntity: vi.fn(), createRelation: vi.fn(), deleteElementById: vi.fn(), updateAttribute: vi.fn() }));
vi.mock('../../../src/database/redis', () => ({ notify: vi.fn((_topic, element) => element), delEditContext: vi.fn(), setEditContext: vi.fn() }));

const caps = (...names: string[]) => names.map((name) => ({ name }));
const phase = { kill_chain_name: 'mitre-attack', phase_name: 'execution', x_opencti_order: 2 };
const existing = { id: 'phase-1', entity_type: ENTITY_TYPE_KILL_CHAIN_PHASE, ...phase };

describe('addKillChainPhase', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.mocked(createEntity).mockResolvedValue({ id: 'new-phase' } as any);
  });

  it('should return an existing phase unchanged to a user who cannot manage kill chain phases', async () => {
    vi.mocked(storeLoadById).mockResolvedValue(existing as any);
    const user: any = { id: 'user-1', capabilities: caps('KNOWLEDGE_KNUPDATE') };
    await expect(addKillChainPhase({}, user, { ...phase, x_opencti_order: 9, update: true })).resolves.toBe(existing);
    expect(storeLoadById).toHaveBeenCalledWith({}, user, generateStandardId(ENTITY_TYPE_KILL_CHAIN_PHASE, phase), ENTITY_TYPE_KILL_CHAIN_PHASE);
    expect(createEntity).not.toHaveBeenCalled();
  });

  it('should refuse to create a new phase to a user who cannot manage kill chain phases', async () => {
    vi.mocked(storeLoadById).mockResolvedValue(undefined as any);
    const user: any = { id: 'user-1', capabilities: caps('KNOWLEDGE_KNUPDATE') };
    await expect(addKillChainPhase({}, user, phase)).rejects.toThrow('You are not allowed to create kill chain phases.');
    expect(createEntity).not.toHaveBeenCalled();
  });

  it('should create or upsert the phase for a user who manages kill chain phases, in main or in the draft scope', async () => {
    const manager: any = { id: 'user-1', capabilities: caps('SETTINGS_SETKILLCHAINPHASES') };
    await expect(addKillChainPhase({}, manager, phase)).resolves.toEqual({ id: 'new-phase' });
    const inDraft: any = { id: 'user-1', capabilities: [], capabilitiesInDraft: caps('SETTINGS_SETKILLCHAINPHASES') };
    await expect(addKillChainPhase({ draft_context: 'draft-1' }, inDraft, phase)).resolves.toEqual({ id: 'new-phase' });
    expect(storeLoadById).not.toHaveBeenCalled();
    // the draft scope only counts in a draft
    vi.mocked(storeLoadById).mockResolvedValue(undefined as any);
    await expect(addKillChainPhase({}, inDraft, phase)).rejects.toThrow('You are not allowed to create kill chain phases.');
  });
});
