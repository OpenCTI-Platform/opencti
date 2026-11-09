import { beforeEach, describe, expect, it, vi } from 'vitest';
import { up } from '../../../src/migrations/1794216991000-project-draft-workflow-status';
import { elUpdateByQueryForMigration } from '../../../src/database/engine';
import { fullEntitiesList } from '../../../src/database/middleware-loader';
import { getWorkflowDefaultState } from '../../../src/modules/workflow/domain/workflow-domain';
import { ENTITY_TYPE_DRAFT_WORKSPACE } from '../../../src/modules/draftWorkspace/draftWorkspace-types';
import { ENTITY_TYPE_WORKFLOW_INSTANCE } from '../../../src/modules/workflow/types/workflow-types';
import { ENTITY_TYPE_STATUS } from '../../../src/schema/internalObject';

vi.mock('../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<any>();
  return { ...actual, logMigration: { info: vi.fn(), error: vi.fn(), warn: vi.fn(), debug: vi.fn() } };
});
vi.mock('../../../src/utils/access', async (importOriginal) => {
  const actual = await importOriginal<any>();
  return { ...actual, executionContext: vi.fn(() => ({ source: 'migration' })) };
});
vi.mock('../../../src/database/engine', () => ({ elUpdateByQueryForMigration: vi.fn() }));
vi.mock('../../../src/database/middleware-loader', () => ({ fullEntitiesList: vi.fn() }));
vi.mock('../../../src/modules/workflow/domain/workflow-domain', () => ({ getWorkflowDefaultState: vi.fn() }));

type Data = { statuses?: any[]; drafts?: any[]; instances?: any[] };
const setData = ({ statuses = [], drafts = [], instances = [] }: Data) => {
  vi.mocked(fullEntitiesList).mockImplementation((async (_context: any, _user: any, types: string[]) => {
    if (types[0] === ENTITY_TYPE_STATUS) return statuses;
    if (types[0] === ENTITY_TYPE_DRAFT_WORKSPACE) return drafts;
    if (types[0] === ENTITY_TYPE_WORKFLOW_INSTANCE) return instances;
    return [];
  }) as any);
};
const runMigration = () => new Promise<void>((resolve, reject) => {
  void up((error) => (error ? reject(error) : resolve()));
});
// draft id -> status id, as sent to the update by query
const projected = () => vi.mocked(elUpdateByQueryForMigration).mock.calls[0][2].script.params.statusIdByDraftId;

const status = (id: string, templateId: string, scope = 'GLOBAL') => ({ id, template_id: templateId, scope });

describe('migration project-draft-workflow-status', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.mocked(getWorkflowDefaultState).mockResolvedValue({ initialState: 'template-new' });
  });

  it('should do nothing when DraftWorkspace has no published workflow', async () => {
    vi.mocked(getWorkflowDefaultState).mockResolvedValue(null);
    await runMigration();
    expect(fullEntitiesList).not.toHaveBeenCalled();
    expect(elUpdateByQueryForMigration).not.toHaveBeenCalled();
  });

  it('should not update anything when there are no drafts', async () => {
    setData({ statuses: [status('status-new', 'template-new')] });
    await runMigration();
    expect(elUpdateByQueryForMigration).not.toHaveBeenCalled();
    // The instances of no draft are not even looked up
    expect(fullEntitiesList).not.toHaveBeenCalledWith(expect.anything(), expect.anything(), [ENTITY_TYPE_WORKFLOW_INSTANCE], expect.anything());
  });

  it('should project the current state of the instance of a draft', async () => {
    setData({
      statuses: [status('status-new', 'template-new'), status('status-review', 'template-review')],
      drafts: [{ internal_id: 'draft-1' }],
      instances: [{ entity_id: 'draft-1', currentState: 'template-review', scope: 'standard' }],
    });
    await runMigration();
    expect(projected()).toEqual({ 'draft-1': 'status-review' });
  });

  it('should project the initial state on a draft without instance, or without current state', async () => {
    setData({
      statuses: [status('status-new', 'template-new')],
      drafts: [{ internal_id: 'draft-1' }, { internal_id: 'draft-2' }],
      instances: [{ entity_id: 'draft-2', scope: 'standard' }],
    });
    await runMigration();
    expect(projected()).toEqual({ 'draft-1': 'status-new', 'draft-2': 'status-new' });
  });

  it('should pick the status of the scope of the instance', async () => {
    setData({
      statuses: [status('status-global', 'template-review'), status('status-other', 'template-review', 'OTHER')],
      drafts: [{ internal_id: 'draft-1' }],
      instances: [{ entity_id: 'draft-1', currentState: 'template-review', scope: 'OTHER' }],
    });
    await runMigration();
    expect(projected()).toEqual({ 'draft-1': 'status-other' });
  });

  it('should skip a draft whose state has no mapped status, or that has no state at all', async () => {
    vi.mocked(getWorkflowDefaultState).mockResolvedValue({ initialState: null });
    setData({
      statuses: [status('status-new', 'template-new')],
      drafts: [{ internal_id: 'draft-unmapped' }, { internal_id: 'draft-no-state' }, { internal_id: 'draft-ok' }],
      instances: [
        { entity_id: 'draft-unmapped', currentState: 'template-unknown', scope: 'standard' },
        { entity_id: 'draft-ok', currentState: 'template-new', scope: 'standard' },
      ],
    });
    await runMigration();
    expect(projected()).toEqual({ 'draft-ok': 'status-new' });
  });

  it('should skip a draft already holding the right status', async () => {
    setData({
      statuses: [status('status-new', 'template-new')],
      drafts: [{ internal_id: 'draft-done', x_opencti_workflow_id: 'status-new' }, { internal_id: 'draft-stale', x_opencti_workflow_id: 'status-old' }],
    });
    await runMigration();
    expect(projected()).toEqual({ 'draft-stale': 'status-new' });
  });

  it('should not run the update when every draft is already projected', async () => {
    setData({
      statuses: [status('status-new', 'template-new')],
      drafts: [{ internal_id: 'draft-done', x_opencti_workflow_id: 'status-new' }],
    });
    await runMigration();
    expect(elUpdateByQueryForMigration).not.toHaveBeenCalled();
  });

  it('should update only the drafts to project, in the internal objects index', async () => {
    setData({
      statuses: [status('status-new', 'template-new')],
      drafts: [{ internal_id: 'draft-1' }],
    });
    await runMigration();
    const [, , body] = vi.mocked(elUpdateByQueryForMigration).mock.calls[0];
    expect(body.query.bool.must).toEqual([
      { term: { 'entity_type.keyword': { value: ENTITY_TYPE_DRAFT_WORKSPACE } } },
      { terms: { 'internal_id.keyword': ['draft-1'] } },
    ]);
    expect(body.script.source).toContain('x_opencti_workflow_id');
  });
});
