import { describe, it, expect } from 'vitest';
import { getUpdateFieldOptions, type UpdateFieldOptionsContext } from './bulkUpdateFieldOptions';

const context = (overrides: Partial<UpdateFieldOptionsContext>): UpdateFieldOptionsContext => ({
  steps: [{ type: 'ADD' }],
  index: 0,
  selectedTypes: ['Intrusion-Set'],
  entityTypeFilterValues: [],
  contextTypes: [],
  isAdmin: false,
  isUserDatatable: false,
  customFieldDefinitionsOfTypes: [],
  t: (text) => text,
  ...overrides,
});

const values = (ctx: UpdateFieldOptionsContext) => getUpdateFieldOptions(ctx).map((option) => option.value);

describe('Update drawer field options', () => {
  it('should offer the fields of an add on entities, sorted by label', () => {
    expect(getUpdateFieldOptions(context({})).map((option) => option.label))
      .toEqual(['External references', 'Labels', 'Marking definitions']);
  });

  it('should offer the creator to admins only', () => {
    expect(values(context({ isAdmin: true }))).toContain('creator_id');
    expect(values(context({ isAdmin: false }))).not.toContain('creator_id');
    expect(values(context({ isAdmin: true, steps: [{ type: 'REMOVE' }] }))).not.toContain('creator_id');
  });

  it('should offer the fields of a replace, depending on the types', () => {
    const fields = values(context({ steps: [{ type: 'REPLACE' }], selectedTypes: ['Intrusion-Set'] }));
    expect(fields).toEqual(expect.arrayContaining(['created-by', 'confidence', 'description', 'x_opencti_score', 'x_opencti_workflow_id']));
    expect(fields).not.toContain('case_severity_ov');
    const caseFields = values(context({ steps: [{ type: 'REPLACE' }], selectedTypes: ['Case-Incident'] }));
    expect(caseFields).toEqual(expect.arrayContaining(['case_severity_ov', 'case_priority_ov', 'incident_response_types_ov', 'object-assignee']));
  });

  it('should not offer the status when several types are selected', () => {
    expect(values(context({ steps: [{ type: 'REPLACE' }], selectedTypes: ['Malware', 'Indicator'] }))).not.toContain('x_opencti_workflow_id');
  });

  it('should offer the start and stop times on relationships only', () => {
    expect(values(context({ selectedTypes: [], entityTypeFilterValues: ['stix-core-relationship'] }))).toContain('start_time');
    expect(values(context({ selectedTypes: ['uses'], contextTypes: ['stix-core-relationship'] }))).toContain('stop_time');
    expect(values(context({}))).not.toContain('start_time');
  });

  it('should offer the user fields on the users list', () => {
    expect(values(context({ isUserDatatable: true, steps: [{ type: 'ADD' }] }))).toEqual(['groups', 'organizations']);
    expect(values(context({ isUserDatatable: true, steps: [{ type: 'REPLACE' }] })))
      .toEqual(['account_lock_after_date', 'account_status', 'password_valid_until']);
    expect(values(context({ isUserDatatable: true, steps: [{}] }))).toEqual([]);
  });

  it('should offer the custom fields, only the multi select ones for an add', () => {
    const customFieldDefinitionsOfTypes = [
      { name: 'x_opencti_cf_tags', label: 'Tags', field_type: 'multi_select' },
      { name: 'x_opencti_cf_note', label: 'Note', field_type: 'text' },
    ];
    expect(values(context({ customFieldDefinitionsOfTypes }))).toContain('x_opencti_cf_tags');
    expect(values(context({ customFieldDefinitionsOfTypes }))).not.toContain('x_opencti_cf_note');
    expect(values(context({ customFieldDefinitionsOfTypes, steps: [{ type: 'REPLACE' }] }))).toContain('x_opencti_cf_note');
  });

  it('should disable a field already replaced in another step', () => {
    const steps = [{ type: 'REPLACE', field: 'description' }, { type: 'REPLACE' }];
    const options = getUpdateFieldOptions(context({ steps, index: 1 }));
    expect(options.find((option) => option.value === 'description')?.disabled).toEqual(true);
    expect(options.find((option) => option.value === 'confidence')?.disabled).toEqual(false);
  });

  it('should disable for a replace a field already used by another step', () => {
    const steps = [{ type: 'ADD', field: 'object-label' }, { type: 'REPLACE' }];
    const options = getUpdateFieldOptions(context({ steps, index: 1 }));
    expect(options.find((option) => option.value === 'object-label')?.disabled).toEqual(true);
  });
});
