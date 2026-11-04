import { vi, describe, it, expect, beforeEach } from 'vitest';
import { formSubmit } from '../../../src/modules/form/form-domain';
import * as draftWorkspaceDomain from '../../../src/modules/draftWorkspace/draftWorkspace-domain';
import * as workDomain from '../../../src/domain/work';
import * as rabbitmq from '../../../src/database/rabbitmq';

const { mockStoreLoadById } = vi.hoisted(() => ({
  mockStoreLoadById: vi.fn(),
}));

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
  pushToWorkerForConnector: vi.fn(),
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

const mockForm: any = {
  id: 'form-1',
  name: 'Test Form',
  form_schema: JSON.stringify({
    fields: [
      { name: 'name', label: 'Name', type: 'text', attributeMapping: { entity: 'main_entity', attributeName: 'name' } },
    ],
    mainEntityType: 'Individual',
  }),
};

describe('formSubmit', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    mockStoreLoadById.mockResolvedValue(mockForm);
  });

  it('should reject submission when the form is not active', async () => {
    const input = {
      formId: 'form-1',
      values: JSON.stringify({ name: 'Test Individual' }),
    };

    mockStoreLoadById.mockResolvedValue({ ...mockForm, active: false });

    await expect(formSubmit(mockContext, mockUser, input, false)).rejects.toThrow('Form is inactive');
    expect(workDomain.createWork).not.toHaveBeenCalled();
    expect(draftWorkspaceDomain.addDraftWorkspace).not.toHaveBeenCalled();
    expect(rabbitmq.pushToWorkerForConnector).not.toHaveBeenCalled();
  });
});
