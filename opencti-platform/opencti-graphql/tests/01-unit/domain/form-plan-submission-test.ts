import { describe, expect, it, vi } from 'vitest';
import { planSubmission } from '../../../src/modules/form/form-domain';

vi.mock('../../../src/database/middleware-loader', () => ({
  storeLoadById: vi.fn(),
  internalLoadById: vi.fn(),
  fullEntitiesList: vi.fn(),
  pageEntitiesConnection: vi.fn(),
}));

vi.mock('../../../src/modules/form/form-validation', () => ({
  validateFormSubmission: vi.fn(),
}));

vi.mock('../../../src/modules/form/form-bundle-builder', () => ({
  buildMainStixEntities: vi.fn().mockResolvedValue({
    mainStixEntities: [{ id: 'report--main' }],
    mainEntityStixId: 'report--main',
  }),
  buildAdditionalEntities: vi.fn().mockResolvedValue(new Map()),
  buildRelationships: vi.fn().mockResolvedValue(undefined),
  wrapInContainerOrPush: vi.fn(),
}));

const mockContext: any = {};
const mockUser: any = { id: 'user-1', capabilities: [] };

describe('planSubmission', () => {
  it('builds a bundle with objects and no draft plan when isDraft is false', async () => {
    const form: any = { id: 'form-1', name: 'Test Form' };
    const input: any = {
      formId: 'form-1',
      values: JSON.stringify({ name: 'Report A' }),
    };
    const schema: any = {
      mainEntityType: 'Report',
      fields: [{ name: 'name', attributeMapping: { entity: 'main_entity', attributeName: 'name' } }],
      includeInContainer: false,
    };
    form.form_schema = JSON.stringify(schema);

    const plan = await planSubmission(mockContext, mockUser, form, input, false);

    expect(plan.bundle.type).toBe('bundle');
    expect(plan.bundle.spec_version).toBe('2.1');
    expect(plan.finalIsDraft).toBe(false);
    expect(plan.mainEntityStixId).toBe('report--main');
    expect(plan.draftPlan).toBeNull();
  });

  it('produces a draftPlan when isDraft is true', async () => {
    const form: any = { id: 'form-1', name: 'Test Form' };
    const schema: any = {
      mainEntityType: 'Report',
      fields: [{ name: 'name', attributeMapping: { entity: 'main_entity', attributeName: 'name' } }],
      includeInContainer: false,
      draftDefaults: { name: { isEditable: true } },
    };
    form.form_schema = JSON.stringify(schema);
    const input: any = { formId: 'form-1', values: JSON.stringify({ name: 'Report A' }) };

    const plan = await planSubmission(mockContext, mockUser, form, input, true);

    expect(plan.finalIsDraft).toBe(true);
    expect(plan.draftPlan).not.toBeNull();
    expect(plan.draftPlan?.draftInput.bypassMandatoryAttributes).toBe(true);
  });
});
