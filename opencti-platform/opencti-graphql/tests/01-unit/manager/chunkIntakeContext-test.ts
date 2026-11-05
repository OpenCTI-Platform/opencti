import { beforeEach, describe, expect, it, vi } from 'vitest';
import { DraftLockedError, FunctionalError, WorkNotALiveError } from '../../../src/config/errors';
import { createIntakeContext } from '../../../src/intake/intake-context';
import { ChunkPoisonError, ChunkRefusedError, createChunkContext } from '../../../src/manager/chunkIntakeManager';

// The chunk intake builds its context with the rules of the HTTP edge (intake-context.ts) and keeps
// the worker's outcome for what the edge refuses: a deleted work or a closed draft is refused (acked
// without execution), an unknown or refused writer is poison (dead letter).

vi.mock('../../../src/manager/managerModule', () => ({ registerManager: vi.fn() }));
vi.mock('../../../src/intake/intake-context', () => ({ createIntakeContext: vi.fn() }));

const MESSAGE = {
  chunk_id: 'chunk-1',
  applicant_id: 'applicant-1',
  work_id: 'work-1',
  draft_id: 'draft-1',
  event_id: 'event-1',
  playbook_id: 'playbook-1',
  synchronized: true,
  previous_standard: 'malware--previous',
  retry_number: 1,
  operations: [{ query: 'mutation MalwareAdd', variables: { input: { createdBy: 'identity--a||M||' } } }],
};

describe('Chunk intake context', () => {
  beforeEach(() => {
    vi.mocked(createIntakeContext).mockReset();
  });

  it('should build the context from the whole envelope of the message, and strip the member marks', async () => {
    vi.mocked(createIntakeContext).mockResolvedValue({ context: {} as any, user: { id: 'applicant-1' } as any });
    const operations = JSON.parse(JSON.stringify(MESSAGE.operations));
    const { context } = await createChunkContext(MESSAGE, operations);
    expect(vi.mocked(createIntakeContext).mock.calls[0][0]).toEqual({
      user_id: undefined,
      applicant_id: 'applicant-1',
      work_id: 'work-1',
      draft_id: 'draft-1',
      event_id: 'event-1',
      playbook_id: 'playbook-1',
      synchronized: true,
      previous_standard: 'malware--previous',
      retry_number: 1,
    });
    expect(operations[0].variables.input.createdBy).toEqual('identity--a');
    expect([...(context as any).memberRefIds]).toEqual(['identity--a']);
  });

  it.each([
    ['a deleted work', WorkNotALiveError(), 'work_not_alive'],
    ['a closed draft', DraftLockedError('Could not find draft workspace'), 'draft_locked'],
  ])('should refuse %s as the worker skips it', async (_label, error, reason) => {
    vi.mocked(createIntakeContext).mockRejectedValue(error);
    const failure = await createChunkContext(MESSAGE, []).catch((e) => e);
    expect(failure).toBeInstanceOf(ChunkRefusedError);
    expect(failure.reason).toEqual(reason);
  });

  it('should treat a writer that cannot be resolved as poison', async () => {
    vi.mocked(createIntakeContext).mockRejectedValue(FunctionalError('Cant impersonate applicant applicant-1'));
    const failure = await createChunkContext(MESSAGE, []).catch((e) => e);
    expect(failure).toBeInstanceOf(ChunkPoisonError);
  });
});
