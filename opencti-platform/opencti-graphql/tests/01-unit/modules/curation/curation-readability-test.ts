import { beforeEach, describe, expect, it, vi } from 'vitest';
import { keepWithReadableParticipants } from '../../../../src/modules/curation/curation-readability';
import { internalFindByIds } from '../../../../src/database/middleware-loader';
import { SYSTEM_USER } from '../../../../src/utils/access';
import { STIX_ORGANIZATIONS_RESTRICTED } from '../../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_CURATION_PROPOSAL, ENTITY_TYPE_MERGE_RECORD } from '../../../../src/modules/curation/curation-types';
import type { BasicStoreBase } from '../../../../src/types/store';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  internalFindByIds: vi.fn(),
}));

const context = { user_inside_platform_organization: false } as unknown as AuthContext;
const analyst = {
  id: 'analyst-id',
  capabilities: [{ name: 'KNOWLEDGE' }],
  organizations: [{ internal_id: 'org-a', standard_id: 'identity--org-a' }],
} as unknown as AuthUser;

const target = { internal_id: 'target', entity_type: 'Intrusion-Set' };
const sharedRecord = { internal_id: 'record-shared', entity_type: 'MergeRecord' };
const otherRecord = { internal_id: 'record-other', entity_type: 'MergeRecord' };

type Split = BasicStoreBase & { record_id: string };
const splitOf = (id: string, recordId: string) => ({ internal_id: id, record_id: recordId }) as unknown as Split;
const participantsOf = (split: Split) => ['target', split.record_id];

describe('the participants of a curation record', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // The store gives the analyst the elements it may read, by markings and organizations: not the other record.
    vi.mocked(internalFindByIds).mockImplementation(async (_context, user, ids) => {
      const stored = user === SYSTEM_USER ? [target, sharedRecord, otherRecord] : [target, sharedRecord];
      return stored.filter((element) => ids.includes(element.internal_id)) as never;
    });
  });

  it('restricts the curation records by organization in the store, as the knowledge they reveal', () => {
    expect(STIX_ORGANIZATIONS_RESTRICTED).toEqual(expect.arrayContaining([ENTITY_TYPE_CURATION_PROPOSAL, ENTITY_TYPE_MERGE_RECORD]));
  });

  it('hides a record naming a participant that exists but that the user cannot read', async () => {
    const kept = await keepWithReadableParticipants(context, analyst, [splitOf('split-shared', 'record-shared'), splitOf('split-other', 'record-other')], participantsOf);
    expect(kept.map((split) => split.internal_id)).toEqual(['split-shared']);
    expect(vi.mocked(internalFindByIds).mock.calls[1][1]).toBe(SYSTEM_USER);
  });

  it('leaves a record naming a participant that no longer exists to its own restrictions', async () => {
    const kept = await keepWithReadableParticipants(context, analyst, [splitOf('split-gone', 'record-gone')], participantsOf);
    expect(kept.map((split) => split.internal_id)).toEqual(['split-gone']);
  });
});
