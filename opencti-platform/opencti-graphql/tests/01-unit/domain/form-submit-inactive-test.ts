import { vi, describe, it, expect, beforeEach } from 'vitest';
import { formSubmit } from '../../../src/modules/form/form-domain';
import * as draftWorkspaceDomain from '../../../src/modules/draftWorkspace/draftWorkspace-domain';
import * as workDomain from '../../../src/domain/work';
import * as rabbitmq from '../../../src/database/rabbitmq';

const { mockStoreLoadById } = vi.hoisted(() => ({
  mockStoreLoadById: vi.fn(),
}));

vi.mock('../../../src/python/pythonBridge', () => ({}));
vi.mock('../../../src/modules/draftWorkspace/draftWorkspace-domain');
vi.mock('../../../src/database/middleware-loader', () => ({
  storeLoadById: mockStoreLoadById,
  internalLoadById: vi.fn(),
  fullEntitiesList: vi.fn(),
  pageEntitiesConnection: vi.fn(),
}));
vi.mock('../../../src/database/middleware', () => ({
  createEntity: vi.fn(),
  deleteElementById: vi.fn(),
  patchAttribute: vi.fn(),
  updateAttribute: vi.fn(),
}));
vi.mock('../../../src/domain/work');
vi.mock('../../../src/database/rabbitmq', () => ({
  pushBundleToWorker: vi.fn(),
  pushToConnector: vi.fn(),
}));
vi.mock('../../../src/manager/telemetryManager', () => ({
  addFormIntakeSubmittedCount: vi.fn().mockResolvedValue(undefined),
}));

const mockUser: any = {
  id: 'user-1',
  individual_id: 'individual-1',
  name: 'User 1',
  origin: { user_id: 'user-1' },
  roles: [],
  groups: [],
  capabilities: [],
  organizations: [],
  allowed_marking: [],
};

const mockContext: any = {
  user: mockUser,
  tracing: {
    getTracer: () => ({ startSpan: () => ({ end: () => {} }) }),
  },
};

const buildForm = (active?: boolean): any => ({
  id: 'form-1',
  name: 'Test Form',
  active,
  form_schema: JSON.stringify({
    fields: [
      { name: 'name', label: 'Name', type: 'text', attributeMapping: { entity: 'main_entity', attributeName: 'name' } },
    ],
    mainEntityType: 'Malware',
  }),
});

const input = { formId: 'form-1', values: JSON.stringify({ name: 'InactiveFormRepro-Malware' }) };

describe('formSubmit on an inactive form', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.spyOn(workDomain, 'createWork').mockResolvedValue({ id: 'work-1' } as any);
    vi.spyOn(draftWorkspaceDomain, 'addDraftWorkspace').mockResolvedValue({ id: 'draft-1' } as any);
  });

  it.each([false, true])('should refuse submission when active is false (isDraft=%s)', async (isDraft) => {
    mockStoreLoadById.mockResolvedValue(buildForm(false));
    await expect(formSubmit(mockContext, mockUser, input, isDraft)).rejects.toThrow('Form is inactive');
    expect(draftWorkspaceDomain.addDraftWorkspace).not.toHaveBeenCalled();
    expect(workDomain.createWork).not.toHaveBeenCalled();
    expect(rabbitmq.pushBundleToWorker).not.toHaveBeenCalled();
  });

  it.each([true, undefined])('should accept submission when active is %s', async (active) => {
    mockStoreLoadById.mockResolvedValue(buildForm(active));
    const result = await formSubmit(mockContext, mockUser, input, false);
    expect(result.success).toBe(true);
    expect(rabbitmq.pushBundleToWorker).toHaveBeenCalled();
  });
});
