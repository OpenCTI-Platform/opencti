import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createWork } from '../../../src/domain/work';
import { elIndex, elLoadById } from '../../../src/database/engine';
import { redisInitializeWork } from '../../../src/database/redis';

vi.mock('../../../src/database/engine', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/database/engine')>();
  return { ...actual, elIndex: vi.fn(), elLoadById: vi.fn() };
});
vi.mock('../../../src/database/redis', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/database/redis')>();
  return { ...actual, redisInitializeWork: vi.fn() };
});

describe('createWork', () => {
  const context = {} as any;
  const user = { id: 'user-1' } as any;
  const connector = { internal_id: 'connector-1', connector_type: 'EXTERNAL_IMPORT' };

  beforeEach(() => {
    vi.mocked(elIndex).mockReset();
    vi.mocked(elLoadById).mockReset();
    vi.mocked(redisInitializeWork).mockReset();
    vi.mocked(elLoadById).mockImplementation((async (_context: any, _user: any, id: string) => ({ internal_id: id })) as any);
  });

  it('should pass the form submission binding to the redis state of the work', async () => {
    const formSubmission = { applicant_id: 'user-1', form_id: 'form-1', draft_id: 'draft-1' };
    const work: any = await createWork(context, user, connector, 'Form submission', 'connector-1', { receivedTime: 'now', formSubmission });
    expect(redisInitializeWork).toHaveBeenCalledExactlyOnceWith(work.id, false, formSubmission);
  });

  it('should not bind a work created without a form submission', async () => {
    const work: any = await createWork(context, user, connector, 'Regular import', 'connector-1', { isMultiPartWork: true });
    expect(redisInitializeWork).toHaveBeenCalledExactlyOnceWith(work.id, true, undefined);
  });

  it('should not initialize the redis state when the work was not stored', async () => {
    vi.mocked(elLoadById).mockResolvedValue(undefined as any);
    await createWork(context, user, connector, 'Form submission', 'connector-1', { formSubmission: { applicant_id: 'user-1', form_id: 'form-1', draft_id: null } });
    expect(redisInitializeWork).not.toHaveBeenCalled();
  });
});
