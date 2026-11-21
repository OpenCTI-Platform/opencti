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
    isExistingMain: [],
  }),
  buildAdditionalEntities: vi.fn().mockResolvedValue(new Map()),
  buildRelationships: vi.fn().mockResolvedValue(undefined),
  wrapInContainerOrPush: vi.fn(),
}));

const mockContext: any = {};
const mockUser: any = { id: 'user-1', capabilities: [{ name: 'KNOWLEDGE_KNUPDATE' }] };
const draftUpdater: any = { id: 'user-3', capabilities: [{ name: 'KNOWLEDGE_KNFORMINTAKE' }], capabilitiesInDraft: [{ name: 'KNOWLEDGE_KNUPDATE' }] };
const formIntakeOnly: any = { id: 'user-2', capabilities: [{ name: 'KNOWLEDGE_KNFORMINTAKE' }] };

describe('planSubmission', () => {
  it('orchestrates the builder pipeline with the right arguments and returns their results as the plan (bundle-population itself is mocked, not exercised)', async () => {
    const { buildMainStixEntities, buildAdditionalEntities, buildRelationships, wrapInContainerOrPush } = await import('../../../src/modules/form/form-bundle-builder');
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

    // Confirms the planner actually wires the builders together (values/schema decoded and
    // threaded through, main entities passed on to relationship-building and container wrapping)
    // rather than just happening to return a well-shaped, still-empty bundle.
    expect(buildMainStixEntities).toHaveBeenCalledWith(mockContext, mockUser, schema, { name: 'Report A' }, 'Report', false, []);
    expect(buildAdditionalEntities).toHaveBeenCalledWith(mockContext, mockUser, schema, { name: 'Report A' }, plan.bundle, false, [], [], true);
    expect(buildRelationships).toHaveBeenCalledWith(mockContext, mockUser, schema, { name: 'Report A' }, [{ id: 'report--main' }], new Map(), plan.bundle);
    expect(wrapInContainerOrPush).toHaveBeenCalledWith('Report', [{ id: 'report--main' }], plan.bundle, false, new Map(), [], []);
  });

  it('lets only an applicant who can update knowledge attach existing tasks, notes or opinions', async () => {
    const { buildAdditionalEntities } = await import('../../../src/modules/form/form-bundle-builder');
    const schema: any = { mainEntityType: 'Report', fields: [], includeInContainer: false };
    const form: any = { id: 'form-1', name: 'Test Form', form_schema: JSON.stringify(schema) };
    const input: any = { formId: 'form-1', values: JSON.stringify({}) };

    await planSubmission(mockContext, formIntakeOnly, form, input, false);

    expect(vi.mocked(buildAdditionalEntities).mock.lastCall?.[8]).toBe(false);
  });

  // Same destination as the import (isCreateOnlyFormImport): the new draft, or the current draft of the applicant
  it.each([
    ['Update knowledge in draft, submitting to a new draft', draftUpdater, {}, true, true],
    ['Update knowledge in draft, submitting from their current draft', draftUpdater, { draft_context: 'draft-1' }, false, true],
    ['Update knowledge in draft, submitting to main', draftUpdater, {}, false, false],
    ['the form capability only, submitting from their current draft', formIntakeOnly, { draft_context: 'draft-1' }, false, false],
  ])('checks the update right in the destination of the import: %s', async (_, applicant, context, isDraft, canUpdate) => {
    const { buildAdditionalEntities } = await import('../../../src/modules/form/form-bundle-builder');
    const schema: any = { mainEntityType: 'Report', fields: [], includeInContainer: false };
    const form: any = { id: 'form-1', name: 'Test Form', form_schema: JSON.stringify(schema) };
    const input: any = { formId: 'form-1', values: JSON.stringify({}) };

    await planSubmission(context as any, applicant, form, input, isDraft);

    expect(vi.mocked(buildAdditionalEntities).mock.lastCall?.[8]).toBe(canUpdate);
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
