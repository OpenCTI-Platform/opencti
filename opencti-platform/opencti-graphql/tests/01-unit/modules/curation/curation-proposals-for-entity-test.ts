import { beforeEach, describe, expect, it, vi } from 'vitest';
import '../../../../src/modules/index';
import { findProposalsForEntity } from '../../../../src/modules/curation/curation-domain';
import { pageWithReadableParticipants } from '../../../../src/modules/curation/curation-readability';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

vi.mock('../../../../src/modules/curation/curation-readability', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/curation/curation-readability')>()),
  pageWithReadableParticipants: vi.fn(async () => ({ edges: [], pageInfo: {} })),
}));

const context = {} as AuthContext;
const user = { id: 'user-id' } as AuthUser;
const optionsOf = () => vi.mocked(pageWithReadableParticipants).mock.calls[0][3] as unknown as { first: number; filters: { filters: unknown[] } };

describe('proposals of an entity', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('filters by kind before the limit, so proposals of other kinds never take the place of the wanted ones', async () => {
    await findProposalsForEntity(context, user, 'entity-id', ['open'], ['merge']);
    expect(optionsOf().first).toBe(50);
    expect(optionsOf().filters.filters).toEqual([
      { key: ['subject_ids'], values: ['entity-id'], operator: 'eq' },
      { key: ['proposal_status'], values: ['open'], operator: 'eq' },
      { key: ['proposal_kind'], values: ['merge'], operator: 'eq' },
    ]);
  });

  it('reads the open proposals of every kind when no status or kind is given', async () => {
    await findProposalsForEntity(context, user, 'entity-id');
    expect(optionsOf().filters.filters).toEqual([
      { key: ['subject_ids'], values: ['entity-id'], operator: 'eq' },
      { key: ['proposal_status'], values: ['open'], operator: 'eq' },
    ]);
  });
});
