import { describe, expect, it } from 'vitest';
import type { Widget, WidgetDataSelection } from './widget';
import type { FilterDefinition } from '../hooks/useAuth';
import type { FilterGroup } from '../filters/filtersHelpers-types';
import type { DashboardVariable } from '../../components/dashboard/dashboard-types';
import {
  applyBreakdownCompatibility,
  AUDITS_BREAKDOWN_FIELDS,
  BREAKDOWN_ALLOWED_REFS,
  BREAKDOWN_LIMIT_OPTIONS,
  canWidgetBreakDown,
  clearBreakdown,
  getBreakdownEditorState,
  getBreakdownEntityTypes,
  getBreakdownFieldOptions,
  getBreakdownLimitOptions,
  getWidgetBreakdownFieldOptions,
  getWidgetBreakdownLimit,
  getWidgetBreakdownOrder,
  getWidgetBreakdownOther,
  isBreakdownFieldSupported,
  resolveBreakdownTypeVariables,
} from './widgetBreakdown';

const workspace = { kind: 'workspace' } as const;

const makeWidget = (overrides: Partial<Widget> = {}, entityTypes: string[] = ['Report']): Widget => ({
  id: 'widget',
  type: 'vertical-bar',
  perspective: 'entities',
  dataSelection: [{
    filters: {
      mode: 'and',
      filters: [{ key: 'entity_type', values: entityTypes, operator: 'eq', mode: 'or' }],
      filterGroups: [],
    },
  }],
  parameters: { breakdownBy: 'entity_type' },
  ...overrides,
} as unknown as Widget);

const makeRelationshipsWidget = (overrides: Partial<Widget> = {}, relationshipTypes: string[] = ['targets']): Widget => ({
  id: 'widget',
  type: 'line',
  perspective: 'relationships',
  dataSelection: [{
    perspective: 'relationships',
    filters: {
      mode: 'and',
      filters: [{ key: 'relationship_type', values: relationshipTypes, operator: 'eq', mode: 'or' }],
      filterGroups: [],
    },
    dynamicFrom: { mode: 'and', filters: [{ key: 'entity_type', values: ['Malware'], operator: 'eq', mode: 'or' }], filterGroups: [] },
  }],
  parameters: { breakdownBy: 'toTypes' },
  ...overrides,
} as unknown as Widget);

describe('canWidgetBreakDown', () => {
  it('accepts every entities time series visualization of a workspace dashboard', () => {
    ['vertical-bar', 'line', 'area', 'heatmap'].forEach((type) => {
      expect(canWidgetBreakDown(makeWidget({ type }), workspace)).toBe(true);
    });
  });

  it('accepts every relationships time series visualization of a workspace dashboard', () => {
    ['vertical-bar', 'line', 'area', 'heatmap'].forEach((type) => {
      expect(canWidgetBreakDown(makeRelationshipsWidget({ type }), workspace)).toBe(true);
    });
    // Older datasets carry no perspective of their own
    const withoutDatasetPerspective = makeRelationshipsWidget();
    withoutDatasetPerspective.dataSelection = [{ ...withoutDatasetPerspective.dataSelection[0], perspective: undefined }];
    expect(canWidgetBreakDown(withoutDatasetPerspective, workspace)).toBe(true);
  });

  it('rejects the relationships widgets that cannot be broken down', () => {
    expect(canWidgetBreakDown(makeRelationshipsWidget({ type: 'donut' }), workspace)).toBe(false);
    const widget = makeRelationshipsWidget();
    expect(canWidgetBreakDown({ ...widget, dataSelection: [...widget.dataSelection, ...widget.dataSelection] }, workspace)).toBe(false);
    // A relationships widget can hold an entities dataset: it is not a dataset of relationships
    expect(canWidgetBreakDown({ ...widget, dataSelection: [{ ...widget.dataSelection[0], perspective: 'entities' }] }, workspace)).toBe(false);
    const customView = { kind: 'custom-view' as const, customViewTargetEntityType: 'Report' };
    expect(canWidgetBreakDown(widget, customView)).toBe(true);
  });

  it('rejects other visualizations, perspectives, several datasets and drafts', () => {
    expect(canWidgetBreakDown(makeWidget({ type: 'donut' }), workspace)).toBe(false);
    expect(canWidgetBreakDown(makeWidget({ perspective: null }), workspace)).toBe(false);
    const widget = makeWidget();
    expect(canWidgetBreakDown({ ...widget, dataSelection: [...widget.dataSelection, ...widget.dataSelection] }, workspace)).toBe(false);
    expect(canWidgetBreakDown(makeWidget({}, ['DraftWorkspace']), workspace)).toBe(false);
  });

  it('configures breakdowns in workspace dashboards and custom views only', () => {
    const customView = { kind: 'custom-view' as const, customViewTargetEntityType: 'Report' };
    expect(canWidgetBreakDown(makeWidget(), customView)).toBe(true);
    // A fintel template writes its widgets in a document
    const fintelTemplate = { kind: 'fintelTemplate' as const, fintelWidgets: [], fintelEntityType: 'Report', fintelEditorValue: '' };
    expect(canWidgetBreakDown(makeWidget(), fintelTemplate)).toBe(false);
    // Without host, the widget alone decides
    expect(canWidgetBreakDown(makeWidget())).toBe(true);
    expect(canWidgetBreakDown(makeWidget({ type: 'donut' }))).toBe(false);
  });

  it('defaults the number of series', () => {
    expect(getWidgetBreakdownLimit({})).toEqual(10);
    expect(getWidgetBreakdownLimit({ breakdownLimit: 50 })).toEqual(50);
  });

  it('offers the number of series of the widget, even one the editor does not offer', () => {
    expect(getBreakdownLimitOptions({})).toEqual(BREAKDOWN_LIMIT_OPTIONS);
    expect(getBreakdownLimitOptions({ breakdownLimit: 20 })).toEqual([5, 10, 20, 50]);
    // The API accepts any number from 1 to 50: an imported widget can hold another
    expect(getBreakdownLimitOptions({ breakdownLimit: 15 })).toEqual([5, 10, 15, 20, 50]);
    expect(getBreakdownLimitOptions({ breakdownLimit: 1 })).toEqual([1, 5, 10, 20, 50]);
    expect(BREAKDOWN_LIMIT_OPTIONS).toEqual([5, 10, 20, 50]);
  });

  it('orders by highest values and leaves the other series out by default', () => {
    expect(getWidgetBreakdownOrder({})).toEqual('desc');
    expect(getWidgetBreakdownOrder({ breakdownOrder: null })).toEqual('desc');
    expect(getWidgetBreakdownOrder({ breakdownOrder: 'asc' })).toEqual('asc');
    expect(getWidgetBreakdownOther(undefined)).toBe(false);
    expect(getWidgetBreakdownOther({ breakdownOther: null })).toBe(false);
    expect(getWidgetBreakdownOther({ breakdownOther: true })).toBe(true);
  });
});

describe('getBreakdownEntityTypes', () => {
  const group = (filters: FilterGroup['filters'], mode: 'and' | 'or' = 'and'): FilterGroup => ({ mode, filters, filterGroups: [] });

  it('reads the entity types the filters restrict to', () => {
    expect(getBreakdownEntityTypes(group([
      { key: 'entity_type', values: ['Report', 'Grouping'], operator: 'eq', mode: 'or' },
      { key: 'objectLabel', values: ['label-id'], operator: 'eq', mode: 'or' },
    ]))).toEqual(['Report', 'Grouping']);
  });

  it('reads a single type whatever the mode of its filter', () => {
    // Left by removing a value from "type = Report AND Grouping"
    expect(getBreakdownEntityTypes(group([{ key: 'entity_type', values: ['Report'], operator: 'eq', mode: 'and' }]))).toEqual(['Report']);
    expect(getBreakdownEntityTypes(group([{ key: 'relationship_type', values: ['targets'], operator: 'eq', mode: 'and' }]), 'relationships')).toEqual(['targets']);
  });

  it('returns no type when the filters do not restrict it for sure', () => {
    expect(getBreakdownEntityTypes(undefined)).toEqual([]);
    // An element is of a single type: several types in "and" are not the types of the dataset
    expect(getBreakdownEntityTypes(group([{ key: 'entity_type', values: ['Report', 'Grouping'], operator: 'eq', mode: 'and' }]))).toEqual([]);
    expect(getBreakdownEntityTypes(group([{ key: 'objectLabel', values: ['label-id'], operator: 'eq', mode: 'or' }]))).toEqual([]);
    expect(getBreakdownEntityTypes(group([{ key: 'entity_type', values: ['Report'], operator: 'not_eq', mode: 'or' }]))).toEqual([]);
    // "type = Report OR label = A" can also return other types
    expect(getBreakdownEntityTypes(group([
      { key: 'entity_type', values: ['Report'], operator: 'eq', mode: 'or' },
      { key: 'objectLabel', values: ['label-id'], operator: 'eq', mode: 'or' },
    ], 'or'))).toEqual([]);
  });

  it('reads the relationship types of a relationships dataset', () => {
    const filters = group([
      { key: 'relationship_type', values: ['targets', 'uses'], operator: 'eq', mode: 'or' },
      { key: 'entity_type', values: ['Report'], operator: 'eq', mode: 'or' },
    ]);
    expect(getBreakdownEntityTypes(filters, 'relationships')).toEqual(['targets', 'uses']);
    expect(getBreakdownEntityTypes(filters)).toEqual(['Report']);
    expect(getBreakdownEntityTypes(group([{ key: 'relationship_type', values: ['uses'], operator: 'not_eq', mode: 'or' }]), 'relationships')).toEqual([]);
    expect(getBreakdownEntityTypes(filters, 'audits')).toEqual([]);
  });
});

describe('getBreakdownFieldOptions', () => {
  const definition = (filterKey: string, type: string, label: string, subEntityTypes: string[]): FilterDefinition => ({
    filterKey, type, label, multiple: true, subEntityTypes, elementsForFilterValuesSearch: [],
  });
  const schema = new Map<string, Map<string, FilterDefinition>>([
    ['Report', new Map([
      ['entity_type', definition('entity_type', 'string', 'Entity type', ['Report'])],
      ['createdBy', definition('createdBy', 'id', 'Author', ['Report'])],
      ['objectLabel', definition('objectLabel', 'id', 'Label', ['Report'])],
      ['report_types', definition('report_types', 'vocabulary', 'Report types', ['Report'])],
      ['name', definition('name', 'string', 'Name', ['Report'])],
      ['objects', definition('objects', 'id', 'Contains', ['Report'])],
      ['externalReferences', definition('externalReferences', 'id', 'External reference', ['Report'])],
      ['killChainPhases', definition('killChainPhases', 'id', 'Kill chain phase', ['Report'])],
      ['published', definition('published', 'date', 'Publication date', ['Report'])],
      ['computed_reliability', definition('computed_reliability', 'vocabulary', 'Reliability', ['Report'])],
      ['draft_change.draft_operation', definition('draft_change.draft_operation', 'enum', 'Draft operation', ['Report'])],
    ])],
    ['Malware', new Map([
      ['createdBy', definition('createdBy', 'id', 'Author', ['Malware'])],
      ['objectLabel', definition('objectLabel', 'id', 'Label', ['Malware'])],
      ['malware_types', definition('malware_types', 'vocabulary', 'Malware types', ['Malware'])],
    ])],
    ['Stix-Core-Object', new Map([
      // the schema lists the entity type itself: it must be offered once
      ['entity_type', definition('entity_type', 'string', 'Entity type', ['Stix-Core-Object', 'Report', 'Malware'])],
      ['createdBy', definition('createdBy', 'id', 'Author', ['Stix-Core-Object', 'Report', 'Malware'])],
      // only some sub types carry report types
      ['report_types', definition('report_types', 'vocabulary', 'Report types', ['Report'])],
    ])],
  ]);
  const keys = (entityTypes: string[]) => getBreakdownFieldOptions(schema, entityTypes).map(({ key }) => key);

  it('offers every field of a single type that can be broken down', () => {
    expect(keys(['Report'])).toEqual(['createdBy', 'objectLabel', 'report_types']);
  });

  it('only offers the allowed references, vocabularies and enums', () => {
    const options = keys(['Report']);
    BREAKDOWN_ALLOWED_REFS.forEach((key) => {
      if (schema.get('Report')?.has(key)) expect(options).toContain(key);
    });
    expect(options).toContain('report_types');
    ['objects', 'externalReferences', 'killChainPhases'].forEach((key) => expect(options).not.toContain(key));
  });

  it('offers the fields shared by several types, and the entity type', () => {
    expect(keys(['Report', 'Malware'])).toEqual(['createdBy', 'entity_type', 'objectLabel']);
  });

  it('offers the fields of the abstract type without type filter', () => {
    expect(keys([])).toEqual(['createdBy', 'entity_type']);
  });

  it('offers the entity type for a single abstract type, which holds several concrete types', () => {
    expect(keys(['Stix-Core-Object'])).toEqual(['createdBy', 'entity_type']);
    // A single concrete type is the entity type of every series
    expect(keys(['Report'])).not.toContain('entity_type');
  });

  it('does not offer the custom fields, which the API cannot break down', () => {
    const withCustomField = new Map(schema);
    withCustomField.set('Report', new Map([
      ...(schema.get('Report') ?? new Map()),
      ['x_opencti_cf_priority', definition('x_opencti_cf_priority', 'enum', 'Priority', ['Report'])],
    ]));
    expect(getBreakdownFieldOptions(withCustomField, ['Report']).map(({ key }) => key)).toEqual(['createdBy', 'objectLabel', 'report_types']);
  });

  describe('relationships', () => {
    const relationshipsSchema = new Map<string, Map<string, FilterDefinition>>([
      ['stix-relationship', new Map([
        ['relationship_type', definition('relationship_type', 'string', 'Relationship type', ['stix-relationship', 'targets', 'uses'])],
        ['createdBy', definition('createdBy', 'id', 'Author', ['stix-relationship', 'targets', 'uses'])],
        ['objectLabel', definition('objectLabel', 'id', 'Label', ['stix-relationship', 'targets', 'uses'])],
        ['objectMarking', definition('objectMarking', 'id', 'Marking', ['stix-relationship', 'targets', 'uses'])],
        ['creator_id', definition('creator_id', 'id', 'Creators', ['stix-relationship', 'targets', 'uses'])],
        ['externalReferences', definition('externalReferences', 'id', 'External reference', ['stix-relationship', 'targets', 'uses'])],
        ['confidence', definition('confidence', 'integer', 'Confidence', ['stix-relationship', 'targets', 'uses'])],
        ['objects', definition('objects', 'id', 'Contains', ['stix-relationship', 'targets', 'uses'])],
      ])],
      ['targets', new Map([
        ['createdBy', definition('createdBy', 'id', 'Author', ['targets'])],
        ['objectMarking', definition('objectMarking', 'id', 'Marking', ['targets'])],
        ['fromId', definition('fromId', 'id', 'Source entity', ['targets'])],
        ['toId', definition('toId', 'id', 'Target entity', ['targets'])],
        ['fromTypes', definition('fromTypes', 'string', 'Source type', ['targets'])],
        ['killChainPhases', definition('killChainPhases', 'id', 'Kill chain phase', ['targets'])],
        ['workflow_id', definition('workflow_id', 'id', 'Status', ['targets'])],
      ])],
      ['uses', new Map([
        ['createdBy', definition('createdBy', 'id', 'Author', ['uses'])],
        ['usage_types', definition('usage_types', 'vocabulary', 'Usage types', ['uses'])],
      ])],
    ]);
    const relationshipKeys = (relationshipTypes: string[]) => getBreakdownFieldOptions(relationshipsSchema, relationshipTypes, 'relationships').map(({ key }) => key);

    it('offers the fields of every relationship, their type and the types of their source and target', () => {
      expect(relationshipKeys([])).toEqual(['createdBy', 'creator_id', 'objectLabel', 'objectMarking', 'relationship_type', 'fromTypes', 'toTypes']);
    });

    it('offers the fields of a single relationship type, without the relationship type', () => {
      expect(relationshipKeys(['targets'])).toEqual(['createdBy', 'objectMarking', 'fromTypes', 'toTypes']);
      expect(relationshipKeys(['uses'])).toEqual(['createdBy', 'fromTypes', 'toTypes', 'usage_types']);
    });

    it('offers the fields shared by several relationship types', () => {
      expect(relationshipKeys(['targets', 'uses'])).toEqual(['createdBy', 'relationship_type', 'fromTypes', 'toTypes']);
    });

    it('never offers the source and target themselves, nor the fields of an unbounded cardinality', () => {
      const options = relationshipKeys(['targets']);
      ['fromId', 'toId', 'objects', 'externalReferences', 'killChainPhases', 'workflow_id', 'entity_type'].forEach((key) => expect(options).not.toContain(key));
    });

    it('orders the fields by their translated label', () => {
      const french: Record<string, string> = {
        Author: 'Auteur',
        Creators: 'Créateurs',
        Label: 'Label',
        Marking: 'Marquage',
        'Relationship type': 'Type de relation',
        'Source type': 'Type de source',
        'Target type': 'Type de cible',
      };
      const translate = (label: string) => french[label] ?? label;
      const labels = getBreakdownFieldOptions(relationshipsSchema, [], 'relationships', translate).map(({ label }) => translate(label));
      expect(labels).toEqual(['Auteur', 'Créateurs', 'Label', 'Marquage', 'Type de cible', 'Type de relation', 'Type de source']);
      // The labels themselves are kept, to be translated where shown
      expect(getBreakdownFieldOptions(relationshipsSchema, [], 'relationships', translate).map(({ label }) => label)).toContain('Target type');
    });

    it('labels the relationships fields', () => {
      const labels = getBreakdownFieldOptions(relationshipsSchema, [], 'relationships').map(({ label }) => label);
      expect(labels).toEqual(expect.arrayContaining(['Relationship type', 'Source type', 'Target type']));
    });

    it('checks the field of a relationships widget against its relationship types', () => {
      const supported = (breakdownBy: string, relationshipTypes?: string[]) => isBreakdownFieldSupported(
        relationshipsSchema,
        { ...makeRelationshipsWidget({}, relationshipTypes), parameters: { breakdownBy } },
      );
      expect(supported('toTypes')).toBe(true);
      expect(supported('objectMarking')).toBe(true);
      expect(supported('usage_types')).toBe(false);
      expect(supported('usage_types', ['uses'])).toBe(true);
      // Not offered for a single relationship type, but accepted: a type variable may hold a single one
      expect(supported('relationship_type')).toBe(true);
      expect(supported('relationship_type', ['targets', 'uses'])).toBe(true);
      // An entities field is not one of the relationships
      expect(supported('entity_type', ['targets', 'uses'])).toBe(false);
    });

    it('offers no field for a perspective that cannot be broken down', () => {
      expect(getBreakdownFieldOptions(relationshipsSchema, [], 'audits')).toEqual([]);
    });
  });

  describe('isBreakdownFieldSupported', () => {
    const supported = (breakdownBy: string, entityTypes?: string[]) => isBreakdownFieldSupported(schema, {
      ...makeWidget({}, entityTypes),
      parameters: { breakdownBy },
    });

    it('accepts a field of the entity type of the dataset', () => {
      expect(supported('createdBy', ['Report'])).toBe(true);
      expect(supported('report_types', ['Report'])).toBe(true);
    });

    it('refuses a field the entity type does not have, or that cannot be broken down', () => {
      expect(supported('report_types', ['Malware'])).toBe(false);
      expect(supported('name', ['Report'])).toBe(false);
    });

    it('accepts the entity type of a single type, not offered but accepted by the API', () => {
      // A type variable offering several types can be set to a single one
      expect(supported('entity_type', ['Report'])).toBe(true);
    });

    it('refuses a field the abstract type has not, without type filter', () => {
      const noTypeFilter = { ...makeWidget(), dataSelection: [{ filters: undefined }], parameters: { breakdownBy: 'objectAssignee' } } as unknown as Widget;
      expect(isBreakdownFieldSupported(schema, noTypeFilter)).toBe(false);
      expect(isBreakdownFieldSupported(schema, { ...noTypeFilter, parameters: { breakdownBy: 'createdBy' } })).toBe(true);
    });

    it('accepts the entity type with several types, and only their common fields', () => {
      expect(supported('entity_type', ['Report', 'Malware'])).toBe(true);
      expect(supported('objectLabel', ['Report', 'Malware'])).toBe(true);
      expect(supported('report_types', ['Report', 'Malware'])).toBe(false);
    });

    it('refuses a widget without breakdown field', () => {
      expect(isBreakdownFieldSupported(schema, makeWidget({ parameters: { breakdownBy: null } }))).toBe(false);
    });

    it('offers and accepts no field for draft workspaces, read from a saved filter', () => {
      const withDrafts = new Map(schema);
      withDrafts.set('DraftWorkspace', new Map([['creator_id', definition('creator_id', 'id', 'Creators', ['DraftWorkspace'])]]));
      // The content of a saved filter, once read: the widget itself holds none, so it is eligible
      const drafts = makeWidget({ parameters: { breakdownBy: 'creator_id' } }, ['DraftWorkspace']);
      expect(getWidgetBreakdownFieldOptions(withDrafts, drafts)).toEqual([]);
      expect(isBreakdownFieldSupported(withDrafts, drafts)).toBe(false);
      // Not even the entity type, accepted for any other dataset
      expect(isBreakdownFieldSupported(withDrafts, { ...drafts, parameters: { breakdownBy: 'entity_type' } })).toBe(false);
      expect(getWidgetBreakdownFieldOptions(withDrafts, makeWidget({}, ['Report'])).length).toBeGreaterThan(0);
    });
  });

  describe('with dashboard variables', () => {
    const VARIABLE_ID = '6f1c3f0e-2b7a-4c1e-9d3a-0a1b2c3d4e5f';
    const token = `$var:${VARIABLE_ID}`;
    const typeVariable = (restriction: DashboardVariable['restriction']): DashboardVariable => ({
      id: VARIABLE_ID, name: 'type', type: 'entityType', defaultValue: null, restriction,
    });

    it('reads a type variable as the types it allows', () => {
      expect(resolveBreakdownTypeVariables([token], [typeVariable({ mode: 'selection', values: ['Report', 'Malware'] })])).toEqual(['Report', 'Malware']);
      expect(resolveBreakdownTypeVariables(['Report', token], [typeVariable({ mode: 'selection', values: ['Report', 'Grouping'] })])).toEqual(['Report', 'Grouping']);
      expect(resolveBreakdownTypeVariables(['Report'], undefined)).toEqual(['Report']);
    });

    it('reads no type, like without type filter, when a variable may hold any type or is unknown', () => {
      expect(resolveBreakdownTypeVariables([token], [typeVariable({ mode: 'none' })])).toEqual([]);
      expect(resolveBreakdownTypeVariables([token], [typeVariable({ mode: 'selection', values: [] })])).toEqual([]);
      expect(resolveBreakdownTypeVariables(['Report', token], [])).toEqual([]);
      expect(resolveBreakdownTypeVariables([token], undefined)).toEqual([]);
      const labelVariable: DashboardVariable = { id: VARIABLE_ID, name: 'label', type: 'label', defaultValue: null, restriction: { mode: 'selection', values: ['Report'] } };
      expect(resolveBreakdownTypeVariables([token], [labelVariable])).toEqual([]);
    });

    it('offers the fields of the types a type variable allows', () => {
      const widget = makeWidget({}, [token]);
      const keys = (variables?: DashboardVariable[]) => getWidgetBreakdownFieldOptions(schema, widget, variables).map(({ key }) => key);
      expect(keys([typeVariable({ mode: 'selection', values: ['Report'] })])).toContain('report_types');
      // Any type: the fields of the abstract type, and the type itself
      expect(keys([typeVariable({ mode: 'none' })])).not.toContain('report_types');
      expect(keys([typeVariable({ mode: 'none' })])).toContain('entity_type');
    });
  });
});

describe('audits breakdown', () => {
  const emptyMap = new Map<string, Map<string, FilterDefinition>>();
  const makeAuditsWidget = (overrides: Partial<Widget> = {}, selectionOverrides: Record<string, unknown> = {}): Widget => ({
    id: 'audits-widget',
    type: 'line',
    perspective: 'audits',
    dataSelection: [{ attribute: 'user_id', filters: { mode: 'and', filters: [], filterGroups: [] }, ...selectionOverrides }],
    parameters: { breakdownBy: 'event_scope' },
    ...overrides,
  } as unknown as Widget);

  it('accepts every audits time series visualization of a workspace dashboard', () => {
    ['vertical-bar', 'line', 'area', 'heatmap'].forEach((type) => {
      expect(canWidgetBreakDown(makeAuditsWidget({ type }), workspace)).toBe(true);
    });
    expect(canWidgetBreakDown(makeAuditsWidget({ type: 'donut' }), workspace)).toBe(false);
    // The history of the entity of a custom view
    expect(canWidgetBreakDown(makeAuditsWidget(), { kind: 'custom-view', customViewTargetEntityType: 'Report' })).toBe(true);
  });

  it('refuses a dataset counting distinct values, the breakdown counting every event', () => {
    ['line', 'area'].forEach((type) => {
      expect(canWidgetBreakDown(makeAuditsWidget({ type }, { unique: true }), workspace)).toBe(false);
    });
    // Bars and heatmaps never count distinct values: a leftover setting does not matter
    expect(canWidgetBreakDown(makeAuditsWidget({ type: 'vertical-bar' }, { unique: true }), workspace)).toBe(true);
    // The entities never count distinct values either
    expect(canWidgetBreakDown(makeWidget({ type: 'line', dataSelection: [{ ...makeWidget().dataSelection[0], unique: true }] }), workspace)).toBe(true);
  });

  it('shows the controls of a widget with several datasets or distinct values, locked with the reason', () => {
    const widget = makeAuditsWidget();
    const severalDatasets = { ...widget, dataSelection: [...widget.dataSelection, ...widget.dataSelection] };
    const distinct = makeAuditsWidget({}, { unique: true });

    expect(getBreakdownEditorState(widget, workspace)).toEqual('editable');
    expect(getBreakdownEditorState(severalDatasets, workspace)).toEqual('several-datasets');
    expect(getBreakdownEditorState(distinct, workspace)).toEqual('distinct-values');
    expect(getBreakdownEditorState({ ...severalDatasets, dataSelection: [distinct.dataSelection[0], widget.dataSelection[0]] }, workspace)).toEqual('several-datasets');
    expect(getBreakdownEditorState(makeAuditsWidget({ type: 'donut' }), workspace)).toEqual('hidden');
    expect(getBreakdownEditorState(makeAuditsWidget(), { kind: 'custom-view', customViewTargetEntityType: 'Report' })).toEqual('editable');
    expect(getBreakdownEditorState(makeAuditsWidget(), { kind: 'fintelTemplate', fintelWidgets: [], fintelEntityType: 'Report', fintelEditorValue: '' })).toEqual('hidden');
  });

  it('offers exactly the fields the API accepts for the logs, whatever the filters', () => {
    // Mirror of HISTORY_BREAKDOWN_FIELDS in opencti-graphql/src/database/middleware.ts
    const apiFields = ['event_type', 'event_scope', 'user_id', 'group_ids', 'organization_ids', 'entity_type', 'context_data.entity_type'];
    expect(AUDITS_BREAKDOWN_FIELDS.map(({ key }) => key)).toEqual(apiFields);
    expect(getWidgetBreakdownFieldOptions(emptyMap, makeAuditsWidget()).map(({ key }) => key)).toEqual(apiFields);
    // In their own order, whatever the language
    const reversed = (label: string) => label.split('').reverse().join('');
    expect(getWidgetBreakdownFieldOptions(emptyMap, makeAuditsWidget(), undefined, reversed).map(({ key }) => key)).toEqual(apiFields);
    ['context_data.id', 'context_data.search', 'context_data.message', 'creator_id', 'createdBy'].forEach((key) => {
      expect(isBreakdownFieldSupported(emptyMap, makeAuditsWidget({ parameters: { breakdownBy: key } }))).toBe(false);
    });
    apiFields.forEach((key) => {
      expect(isBreakdownFieldSupported(emptyMap, makeAuditsWidget({ parameters: { breakdownBy: key } }))).toBe(true);
    });
  });

  it('keeps the entities fields to the entities', () => {
    // An entities field carried over to an audits widget is not supported, and the reverse
    expect(isBreakdownFieldSupported(emptyMap, makeAuditsWidget({ parameters: { breakdownBy: 'objectLabel' } }))).toBe(false);
    expect(isBreakdownFieldSupported(emptyMap, makeWidget({ parameters: { breakdownBy: 'event_scope' } }))).toBe(false);
  });
});

describe('applyBreakdownCompatibility', () => {
  const selection = { filters: { mode: 'and', filters: [], filterGroups: [] } } as unknown as WidgetDataSelection;
  const brokenDownLine = {
    type: 'line',
    perspective: 'entities' as const,
    dataSelection: [selection],
    parameters: { breakdownBy: 'entity_type' as const, breakdownLimit: 20, breakdownOrder: 'asc' as const, breakdownOther: true },
  };

  it('keeps the breakdown of every entities time series visualization', () => {
    ['line', 'area', 'vertical-bar', 'heatmap'].forEach((type) => {
      const { parameters } = applyBreakdownCompatibility({ ...brokenDownLine, type }, workspace);
      expect(parameters).toEqual(brokenDownLine.parameters);
    });
  });

  it('drops the breakdown and its settings for a non time series visualization', () => {
    const widget = applyBreakdownCompatibility({ ...brokenDownLine, type: 'donut' }, workspace);
    expect(widget.parameters).toEqual({ breakdownBy: null, breakdownLimit: null, breakdownOrder: null, breakdownOther: null });
  });

  it('keeps the breakdown of every relationships time series visualization', () => {
    const relationships = { ...brokenDownLine, perspective: 'relationships' as const, parameters: { ...brokenDownLine.parameters, breakdownBy: 'toTypes' } };
    ['line', 'area', 'vertical-bar', 'heatmap'].forEach((type) => {
      expect(applyBreakdownCompatibility({ ...relationships, type }, workspace).parameters).toEqual(relationships.parameters);
    });
    // A relationships widget left with an entities dataset cannot be broken down as relationships
    const entitiesDataset = { ...selection, perspective: 'entities' as const };
    expect(applyBreakdownCompatibility({ ...relationships, dataSelection: [entitiesDataset] }, workspace).parameters.breakdownBy).toBeNull();
  });

  it('drops the breakdown without perspective, with several datasets or another host', () => {
    expect(applyBreakdownCompatibility({ ...brokenDownLine, perspective: null }, workspace).parameters.breakdownBy).toBeNull();
    expect(applyBreakdownCompatibility({ ...brokenDownLine, dataSelection: [selection, selection] }, workspace).parameters.breakdownBy).toBeNull();
    const fintelTemplate = { kind: 'fintelTemplate' as const, fintelWidgets: [], fintelEntityType: 'Report', fintelEditorValue: '' };
    expect(applyBreakdownCompatibility(brokenDownLine, fintelTemplate).parameters.breakdownBy).toBeNull();
    // A custom view keeps it: editing an imported broken down widget does not lose its breakdown
    const customView = { kind: 'custom-view' as const, customViewTargetEntityType: 'Report' };
    expect(applyBreakdownCompatibility(brokenDownLine, customView).parameters).toEqual(brokenDownLine.parameters);
    const severalDatasets = applyBreakdownCompatibility({ ...brokenDownLine, dataSelection: [selection, selection] }, workspace);
    expect(severalDatasets.parameters).toEqual({ breakdownBy: null, breakdownLimit: null, breakdownOrder: null, breakdownOther: null });
  });

  it('keeps the breakdown of every audits time series visualization', () => {
    ['line', 'area', 'vertical-bar', 'heatmap'].forEach((type) => {
      const { parameters } = applyBreakdownCompatibility({ ...brokenDownLine, perspective: 'audits' as const, type }, workspace);
      expect(parameters).toEqual(brokenDownLine.parameters);
    });
  });

  it('drops the breakdown of audits lines and areas counting distinct values', () => {
    const distinct = { ...brokenDownLine, perspective: 'audits' as const, dataSelection: [{ ...selection, unique: true }] };
    expect(applyBreakdownCompatibility(distinct, workspace).parameters).toEqual({ breakdownBy: null, breakdownLimit: null, breakdownOrder: null, breakdownOther: null });
    expect(applyBreakdownCompatibility({ ...distinct, type: 'vertical-bar' }, workspace).parameters).toEqual(brokenDownLine.parameters);
  });

  it('returns the widget untouched without breakdown', () => {
    const widget = { ...brokenDownLine, type: 'donut', parameters: { title: 'Donut' } };
    expect(applyBreakdownCompatibility(widget, workspace)).toBe(widget);
  });
});

describe('clearBreakdown', () => {
  it('clears the field and its settings, and keeps the other parameters', () => {
    const widget = { type: 'line', parameters: { title: 'Reports', interval: 'month', breakdownBy: 'entity_type', breakdownLimit: 20, breakdownOrder: 'asc' as const, breakdownOther: true } };
    expect(clearBreakdown(widget)).toEqual({
      type: 'line',
      parameters: { title: 'Reports', interval: 'month', breakdownBy: null, breakdownLimit: null, breakdownOrder: null, breakdownOther: null },
    });
    expect(widget.parameters.breakdownBy).toEqual('entity_type');
  });
});
