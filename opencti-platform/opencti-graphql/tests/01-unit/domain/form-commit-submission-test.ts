import { beforeEach, describe, expect, it, vi } from 'vitest';
import { commitSubmission } from '../../../src/modules/form/form-domain';
import { connectorIdFromIngestId } from '../../../src/domain/connector';
import * as draftWorkspaceDomain from '../../../src/modules/draftWorkspace/draftWorkspace-domain';
import * as workDomain from '../../../src/domain/work';
import * as rabbitmq from '../../../src/database/rabbitmq';
import * as middleware from '../../../src/database/middleware';
import { ENTITY_TYPE_DRAFT_WORKSPACE } from '../../../src/modules/draftWorkspace/draftWorkspace-types';
import { SYSTEM_USER } from '../../../src/utils/access';

vi.mock('../../../src/modules/draftWorkspace/draftWorkspace-domain');
vi.mock('../../../src/domain/work');
vi.mock('../../../src/database/rabbitmq', () => ({ pushBundleToWorker: vi.fn() }));
vi.mock('../../../src/database/middleware', () => ({ patchAttribute: vi.fn() }));
vi.mock('../../../src/manager/telemetryManager', () => ({
  addFormIntakeSubmittedCount: vi.fn().mockResolvedValue(undefined),
}));

const mockUser: any = { id: 'user-1' };
const mockContext: any = {};

describe('commitSubmission', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(workDomain.createWork).mockResolvedValue({ id: 'work-1' } as any);
    vi.mocked(draftWorkspaceDomain.addDraftWorkspace).mockResolvedValue({ id: 'draft-1' } as any);
  });

  it('creates a work item and pushes the bundle without a draft when finalIsDraft is false', async () => {
    const plan: any = {
      bundle: { id: 'bundle--1', objects: [] },
      mainEntityStixId: 'stix-1',
      finalIsDraft: false,
      draftPlan: null,
    };

    const result = await commitSubmission(mockContext, mockUser, 'form-1', plan);

    expect(result.success).toBe(true);
    expect(result.entityId).toBe('stix-1');
    const connectorId = connectorIdFromIngestId('form-1');
    expect(vi.mocked(rabbitmq.pushBundleToWorker)).toHaveBeenCalledWith(
      mockContext,
      SYSTEM_USER,
      connectorId,
      {
        type: 'bundle',
        applicant_id: mockUser.id,
        content: Buffer.from(JSON.stringify(plan.bundle), 'utf-8').toString('base64'),
        work_id: 'work-1',
        draft_id: null,
        update: true,
        no_split: true,
      },
    );
  });

  it('creates a draft workspace and patches its creator_id when finalIsDraft is true', async () => {
    const plan: any = {
      bundle: { id: 'bundle--2', objects: [] },
      mainEntityStixId: undefined,
      finalIsDraft: true,
      draftPlan: { draftInput: { name: 'My Draft', bypassMandatoryAttributes: true } },
    };

    const result = await commitSubmission(mockContext, mockUser, 'form-1', plan);

    expect(result.entityId).toBe('draft-1');
    expect(vi.mocked(draftWorkspaceDomain.addDraftWorkspace)).toHaveBeenCalledWith(
      mockContext,
      SYSTEM_USER,
      plan.draftPlan.draftInput,
    );
    expect(vi.mocked(middleware.patchAttribute)).toHaveBeenCalledWith(
      mockContext,
      SYSTEM_USER,
      'draft-1',
      ENTITY_TYPE_DRAFT_WORKSPACE,
      { creator_id: [mockUser.id] },
    );
    const connectorId = connectorIdFromIngestId('form-1');
    expect(vi.mocked(rabbitmq.pushBundleToWorker)).toHaveBeenCalledWith(
      mockContext,
      SYSTEM_USER,
      connectorId,
      {
        type: 'bundle',
        applicant_id: mockUser.id,
        content: Buffer.from(JSON.stringify(plan.bundle), 'utf-8').toString('base64'),
        work_id: 'work-1',
        draft_id: 'draft-1',
        update: true,
        no_split: true,
      },
    );
  });
});
