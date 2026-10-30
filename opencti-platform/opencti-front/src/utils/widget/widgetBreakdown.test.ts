import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Widget } from './widget';
import type { FilterDefinition } from '../hooks/useAuth';
import type { FilterGroup } from '../filters/filtersHelpers-types';
import type { DashboardVariable } from '../../components/dashboard/dashboard-types';
import { dayStartDate, daysAgo, monthsAgo } from '../Time';
import {
  AUDITS_BREAKDOWN_FIELDS,
  BREAKDOWN_ALLOWED_REFS,
  BREAKDOWN_LIMIT_OPTIONS,
  coarsenSeriesForRendering,
  getBreakdownEntityTypes,
  getBreakdownDefaultStartDate,
  getBreakdownFieldOptions,
  getBreakdownLimitOptions,
  getBreakdownTickAmount,
  getRenderedBarsBudget,
  getRenderedPointsBudget,
  getWidgetBreakdownFieldOptions,
  getWidgetBreakdownLimit,
  getWidgetBreakdownLockReason,
  getWidgetBreakdownOrder,
  getWidgetBreakdownOther,
  hasWidgetBreakdown,
  isBreakdownFieldSupported,
  isBreakdownTypeField,
  isWidgetBreakdownActive,
  isWidgetBreakdownConfigurable,
  isSameBreakdown,
  isWidgetBreakdownEligible,
  resolveBreakdownTypeVariables,
  MAX_RENDERED_BARS,
  MAX_RENDERED_HEATMAP_CELLS,
  MAX_RENDERED_LINE_POINTS,
  MIN_RENDERED_BARS,
  nextBreakdownChartWidth,
  numberSharedSeriesNames,
  scheduleChartDraw,
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

// One point per UTC day, starting on a given date
const daily = (start: string, values: number[]) => values.map((y, i) => {
  const x = new Date(start);
  x.setUTCDate(x.getUTCDate() + i);
  return { x, y };
});

describe('widget breakdown eligibility', () => {
  it('accepts every entities time series visualization of a workspace dashboard', () => {
    ['vertical-bar', 'line', 'area', 'heatmap'].forEach((type) => {
      expect(isWidgetBreakdownActive(makeWidget({ type }), workspace)).toBe(true);
    });
  });

  it('accepts every relationships time series visualization of a workspace dashboard', () => {
    ['vertical-bar', 'line', 'area', 'heatmap'].forEach((type) => {
      expect(isWidgetBreakdownActive(makeRelationshipsWidget({ type }), workspace)).toBe(true);
    });
    // Older datasets carry no perspective of their own
    const withoutDatasetPerspective = makeRelationshipsWidget();
    withoutDatasetPerspective.dataSelection = [{ ...withoutDatasetPerspective.dataSelection[0], perspective: undefined }];
    expect(isWidgetBreakdownEligible(withoutDatasetPerspective, workspace)).toBe(true);
  });

  it('rejects the relationships widgets that cannot be broken down', () => {
    expect(isWidgetBreakdownEligible(makeRelationshipsWidget({ type: 'donut' }), workspace)).toBe(false);
    const widget = makeRelationshipsWidget();
    expect(isWidgetBreakdownEligible({ ...widget, dataSelection: [...widget.dataSelection, ...widget.dataSelection] }, workspace)).toBe(false);
    // A relationships widget can hold an entities dataset: it is not a dataset of relationships
    expect(isWidgetBreakdownEligible({ ...widget, dataSelection: [{ ...widget.dataSelection[0], perspective: 'entities' }] }, workspace)).toBe(false);
    const customView = { kind: 'custom-view' as const, customViewTargetEntityType: 'Report' };
    expect(isWidgetBreakdownActive(widget, customView)).toBe(true);
    expect(hasWidgetBreakdown(widget)).toBe(true);
  });

  it('rejects other visualizations, perspectives, several datasets and drafts', () => {
    expect(isWidgetBreakdownEligible(makeWidget({ type: 'donut' }), workspace)).toBe(false);
    expect(isWidgetBreakdownEligible(makeWidget({ perspective: null }), workspace)).toBe(false);
    const widget = makeWidget();
    expect(isWidgetBreakdownEligible({ ...widget, dataSelection: [...widget.dataSelection, ...widget.dataSelection] }, workspace)).toBe(false);
    expect(isWidgetBreakdownEligible(makeWidget({}, ['DraftWorkspace']), workspace)).toBe(false);
  });

  it('renders and configures breakdowns in workspace dashboards and custom views only', () => {
    const customView = { kind: 'custom-view' as const, customViewTargetEntityType: 'Report' };
    expect(isWidgetBreakdownActive(makeWidget(), customView)).toBe(true);
    expect(isWidgetBreakdownEligible(makeWidget(), customView)).toBe(true);
    // A fintel template writes its widgets in a document
    const fintelTemplate = { kind: 'fintelTemplate' as const, fintelWidgets: [], fintelEntityType: 'Report', fintelEditorValue: '' };
    expect(isWidgetBreakdownActive(makeWidget(), fintelTemplate)).toBe(false);
    expect(isWidgetBreakdownEligible(makeWidget(), fintelTemplate)).toBe(false);
    expect(isWidgetBreakdownActive(makeWidget(), undefined)).toBe(false);
    // ...but still knows the widget is broken down, to refuse it elsewhere
    expect(hasWidgetBreakdown(makeWidget())).toBe(true);
  });

  it('needs a breakdown field', () => {
    expect(isWidgetBreakdownActive(makeWidget({ parameters: { breakdownBy: null } }), workspace)).toBe(false);
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

describe('isBreakdownTypeField', () => {
  it('knows the fields whose values are entity or relationship types', () => {
    ['entity_type', 'relationship_type', 'fromTypes', 'toTypes'].forEach((field) => expect(isBreakdownTypeField(field)).toBe(true));
    ['objectLabel', 'creator_id', null, undefined].forEach((field) => expect(isBreakdownTypeField(field)).toBe(false));
  });
});

describe('getBreakdownDefaultStartDate', () => {
  it('only looks back 30 days for a daily breakdown', () => {
    expect(getBreakdownDefaultStartDate('day')).toEqual(daysAgo(30));
  });

  it('looks back 12 months for the other intervals', () => {
    ['week', 'month', 'quarter', 'year'].forEach((interval) => {
      expect(getBreakdownDefaultStartDate(interval)).toEqual(monthsAgo(12));
    });
  });

  it('looks back from the end date of the dashboard, which can be long ago', () => {
    const endDate = '2024-03-31T12:00:00.000Z';
    const endDay = dayStartDate(endDate);
    const dailyStart = new Date(getBreakdownDefaultStartDate('day', endDate));
    expect(dailyStart.getTime()).toEqual(new Date(endDay.getFullYear(), endDay.getMonth(), endDay.getDate() - 30).getTime());
    expect(dailyStart.getTime()).toBeLessThan(new Date(endDate).getTime());
    ['week', 'month', 'quarter', 'year'].forEach((interval) => {
      const start = new Date(getBreakdownDefaultStartDate(interval, endDate));
      expect(start.getTime()).toEqual(new Date(endDay.getFullYear() - 1, endDay.getMonth(), endDay.getDate()).getTime());
    });
    // Without end date, from today
    expect(getBreakdownDefaultStartDate('day', null)).toEqual(daysAgo(30));
    expect(getBreakdownDefaultStartDate('month', undefined)).toEqual(monthsAgo(12));
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

describe('rendered bars budget', () => {
  it('follows the width, within the minimum and maximum', () => {
    expect(getRenderedBarsBudget(800)).toEqual(400);
    expect(getRenderedBarsBudget(801)).toEqual(400);
    expect(getRenderedBarsBudget(100)).toEqual(MIN_RENDERED_BARS);
    expect(getRenderedBarsBudget(5000)).toEqual(MAX_RENDERED_BARS);
  });

  it('gives the maximum when the width is unknown', () => {
    expect(getRenderedBarsBudget(0)).toEqual(MAX_RENDERED_BARS);
    expect(getRenderedBarsBudget(-10)).toEqual(MAX_RENDERED_BARS);
    expect(getRenderedBarsBudget(Number.NaN)).toEqual(MAX_RENDERED_BARS);
  });
});

describe('rendered points budget', () => {
  it('shares the bars budget between every series', () => {
    expect(getRenderedPointsBudget('vertical-bar', 800, 20)).toEqual(getRenderedBarsBudget(800));
  });

  it('gives each line or area series a point every 2 pixels', () => {
    expect(getRenderedPointsBudget('line', 700, 1)).toEqual(350);
    expect(getRenderedPointsBudget('area', 700, 10)).toEqual(350 * 10);
  });

  it('gives each heatmap series a cell every 6 pixels', () => {
    expect(getRenderedPointsBudget('heatmap', 600, 10)).toEqual(100 * 10);
  });

  it('keeps a few points per series on a tiny or unknown width', () => {
    expect(getRenderedPointsBudget('heatmap', 12, 2)).toEqual(10 * 2);
    expect(getRenderedPointsBudget('line', 0, 1)).toEqual((MAX_RENDERED_BARS * 2) / 2);
  });

  it('caps the points of a wide chart with many series, keeping a few points per series', () => {
    expect(getRenderedPointsBudget('line', 2000, 50)).toEqual(MAX_RENDERED_LINE_POINTS);
    expect(getRenderedPointsBudget('heatmap', 1200, 20)).toEqual(MAX_RENDERED_HEATMAP_CELLS);
    expect(getRenderedPointsBudget('heatmap', 600, 200)).toEqual(10 * 200);
  });
});

describe('isSameBreakdown', () => {
  const breakdown = (values: number[], overrides = {}) => ({
    truncated: false,
    dates: ['2025-10-01T00:00:00.000Z', '2025-10-02T00:00:00.000Z'],
    series: [{ label: 'user-id', isOther: false, entity: { id: 'user-id', name: 'Alice' }, values }],
    ...overrides,
  });

  it('finds a refreshed breakdown with the same values the same', () => {
    expect(isSameBreakdown(breakdown([1, 2]), breakdown([1, 2]))).toBe(true);
    expect(isSameBreakdown(null, null)).toBe(true);
  });

  it('finds a breakdown with other values, dates, series or names different', () => {
    expect(isSameBreakdown(breakdown([1, 2]), breakdown([1, 3]))).toBe(false);
    expect(isSameBreakdown(breakdown([1, 2]), breakdown([1, 2], { truncated: true }))).toBe(false);
    expect(isSameBreakdown(breakdown([1, 2]), breakdown([1, 2], { dates: ['2025-10-02T00:00:00.000Z', '2025-10-03T00:00:00.000Z'] }))).toBe(false);
    expect(isSameBreakdown(breakdown([1, 2]), breakdown([1, 2], { series: [] }))).toBe(false);
    const renamed = breakdown([1, 2], { series: [{ label: 'user-id', isOther: false, entity: { id: 'user-id', name: 'Bob' }, values: [1, 2] }] });
    expect(isSameBreakdown(breakdown([1, 2]), renamed)).toBe(false);
    expect(isSameBreakdown(breakdown([1, 2]), null)).toBe(false);
  });
});

describe('scheduleChartDraw', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.runAllTimers();
    vi.useRealTimers();
  });

  it('draws the first chart at once, and the charts drawn with it one per task', () => {
    const draws: string[] = [];
    scheduleChartDraw(() => draws.push('first'));
    scheduleChartDraw(() => draws.push('second'));
    scheduleChartDraw(() => draws.push('third'));
    expect(draws).toEqual(['first']);
    vi.advanceTimersToNextTimer();
    expect(draws).toEqual(['first', 'second']);
    vi.advanceTimersToNextTimer();
    expect(draws).toEqual(['first', 'second', 'third']);

    // Once every chart is drawn, the next one is drawn at once
    vi.runAllTimers();
    scheduleChartDraw(() => draws.push('later'));
    expect(draws).toEqual(['first', 'second', 'third', 'later']);
  });

  it('does not draw a cancelled chart', () => {
    const draws: string[] = [];
    scheduleChartDraw(() => draws.push('first'));
    const cancel = scheduleChartDraw(() => draws.push('second'));
    scheduleChartDraw(() => draws.push('third'));
    cancel();
    vi.advanceTimersToNextTimer();
    expect(draws).toEqual(['first', 'third']);
  });
});

describe('nextBreakdownChartWidth', () => {
  it('takes the first measured width', () => {
    expect(nextBreakdownChartWidth(undefined, 800)).toEqual(800);
  });

  it('keeps the previous width on a small resize, and changes it from 20 %', () => {
    expect(nextBreakdownChartWidth(800, 900)).toEqual(800); // +12.5 %
    expect(nextBreakdownChartWidth(800, 700)).toEqual(800); // -12.5 %
    expect(nextBreakdownChartWidth(800, 960)).toEqual(960); // +20 %
    expect(nextBreakdownChartWidth(800, 500)).toEqual(500);
  });
});

describe('getBreakdownTickAmount', () => {
  it('gives a label per 60 pixels, at least 2', () => {
    expect(getBreakdownTickAmount(1200)).toEqual(20);
    expect(getBreakdownTickAmount(130)).toEqual(2);
    expect(getBreakdownTickAmount(0)).toEqual(2);
  });
});

describe('coarsenSeriesForRendering', () => {
  it('keeps the series untouched under the budget', () => {
    const series = [{ name: 'A', data: daily('2026-01-01T00:00:00.000Z', [1, 2, 3]) }];
    const result = coarsenSeriesForRendering(series, 'day', 10);
    expect(result.interval).toEqual('day');
    expect(result.series).toBe(series);
    expect(result.pointsCount).toEqual(3);
  });

  it('sums days into weeks starting on Monday', () => {
    // 2026-01-01 is a Thursday: Thu-Sun belong to the week of Monday 2025-12-29
    const series = [{ name: 'A', data: daily('2026-01-01T00:00:00.000Z', [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]) }];
    const result = coarsenSeriesForRendering(series, 'day', 5);
    expect(result.interval).toEqual('week');
    expect(result.series[0].data).toEqual([
      { x: new Date('2025-12-29T00:00:00.000Z'), y: 1 + 2 + 3 + 4 },
      { x: new Date('2026-01-05T00:00:00.000Z'), y: 5 + 6 + 7 + 8 + 9 + 10 },
    ]);
    expect(result.series[0].name).toEqual('A');
  });

  it('keeps getting coarser until the budget is met, without losing any count', () => {
    const values = Array.from({ length: 366 }, (_, i) => i % 7);
    const series = Array.from({ length: 20 }, (_, i) => ({ name: `S${i}`, data: daily('2025-10-01T00:00:00.000Z', values) }));
    const total = values.reduce((sum, value) => sum + value, 0);

    const toWeeks = coarsenSeriesForRendering(series, 'day', 1200);
    expect(toWeeks.interval).toEqual('week');
    expect(toWeeks.pointsCount).toBeLessThanOrEqual(1200);

    const toMonths = coarsenSeriesForRendering(series, 'day', 600);
    expect(toMonths.interval).toEqual('month');
    expect(toMonths.series[0].data).toHaveLength(13); // October 2025 to October 2026 included
    toMonths.series.forEach((serie) => {
      expect(serie.data.reduce((sum, point) => sum + point.y, 0)).toEqual(total);
    });
    expect(toMonths.weeksCountedByMonday).toBe(false);
  });

  it('coarsens a week series with a smaller budget', () => {
    const values = Array.from({ length: 366 }, (_, i) => i % 7);
    const series = [{ name: 'A', data: daily('2025-10-01T00:00:00.000Z', values) }];
    expect(coarsenSeriesForRendering(series, 'day', MIN_RENDERED_BARS).interval).toEqual('week');
    const result = coarsenSeriesForRendering(series, 'week', 20);
    expect(result.interval).toEqual('month');
    expect(result.pointsCount).toEqual(13);
  });

  it('tells when weeks are counted in the month, quarter or year of their Monday', () => {
    // The week of Monday 2026-03-30 ends in April: it is counted in March, and in the first quarter
    const weekly = [
      { x: new Date('2026-03-23T00:00:00.000Z'), y: 1 },
      { x: new Date('2026-03-30T00:00:00.000Z'), y: 2 },
      { x: new Date('2026-04-06T00:00:00.000Z'), y: 4 },
    ];
    const series = [{ name: 'A', data: weekly }];
    const toMonths = coarsenSeriesForRendering(series, 'week', 2);
    expect(toMonths.interval).toEqual('month');
    expect(toMonths.series[0].data).toEqual([
      { x: new Date('2026-03-01T00:00:00.000Z'), y: 1 + 2 },
      { x: new Date('2026-04-01T00:00:00.000Z'), y: 4 },
    ]);
    expect(toMonths.weeksCountedByMonday).toBe(true);
    const toYears = coarsenSeriesForRendering(series, 'week', 1);
    expect(toYears.interval).toEqual('year');
    expect(toYears.weeksCountedByMonday).toBe(true);

    // Weeks drawn as weeks, or weeks summed from days, keep every count where it belongs
    expect(coarsenSeriesForRendering(series, 'week', 3).weeksCountedByMonday).toBe(false);
    expect(coarsenSeriesForRendering([{ name: 'A', data: daily('2026-03-23T00:00:00.000Z', [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]) }], 'day', 5))
      .toMatchObject({ interval: 'week', weeksCountedByMonday: false });
  });

  it('never goes beyond years', () => {
    const series = [{ name: 'A', data: daily('2026-01-01T00:00:00.000Z', [1, 2]) }];
    const result = coarsenSeriesForRendering(series, 'year', 1);
    expect(result.interval).toEqual('year');
    expect(result.series).toBe(series);
  });
});

describe('numberSharedSeriesNames', () => {
  it('numbers by order the series sharing a name, and only them', () => {
    expect(numberSharedSeriesNames(['Restricted', 'Alice', 'Restricted', 'Bob', 'Restricted']))
      .toEqual(['Restricted (1)', 'Alice', 'Restricted (2)', 'Bob', 'Restricted (3)']);
    expect(numberSharedSeriesNames(['Alice', 'Bob'])).toEqual(['Alice', 'Bob']);
    expect(numberSharedSeriesNames([])).toEqual([]);
  });

  it('skips the numbers other series are already named with', () => {
    expect(numberSharedSeriesNames(['Alice', 'Alice', 'Alice (1)'])).toEqual(['Alice (2)', 'Alice (3)', 'Alice (1)']);
    expect(numberSharedSeriesNames(['Alice (2)', 'Alice', 'Alice', 'Alice', 'Alice (4)'])).toEqual(['Alice (2)', 'Alice (1)', 'Alice (3)', 'Alice (5)', 'Alice (4)']);
    // Shared numbered names are numbered too, apart from the others
    const names = numberSharedSeriesNames(['Alice', 'Alice', 'Alice (1)', 'Alice (1)']);
    expect(names).toEqual(['Alice (2)', 'Alice (3)', 'Alice (1) (1)', 'Alice (1) (2)']);
    expect(new Set(names).size).toEqual(names.length);
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
      expect(isWidgetBreakdownActive(makeAuditsWidget({ type }), workspace)).toBe(true);
    });
    expect(isWidgetBreakdownEligible(makeAuditsWidget({ type: 'donut' }), workspace)).toBe(false);
    // The history of the entity of a custom view
    expect(isWidgetBreakdownActive(makeAuditsWidget(), { kind: 'custom-view', customViewTargetEntityType: 'Report' })).toBe(true);
    // ...but still knows the widget is broken down, to refuse it elsewhere
    expect(hasWidgetBreakdown(makeAuditsWidget())).toBe(true);
  });

  it('refuses a dataset counting distinct values, the breakdown counting every event', () => {
    ['line', 'area'].forEach((type) => {
      expect(isWidgetBreakdownEligible(makeAuditsWidget({ type }, { unique: true }), workspace)).toBe(false);
    });
    // Bars and heatmaps never count distinct values: a leftover setting does not matter
    expect(isWidgetBreakdownEligible(makeAuditsWidget({ type: 'vertical-bar' }, { unique: true }), workspace)).toBe(true);
    // The entities never count distinct values either
    expect(isWidgetBreakdownEligible(makeWidget({ type: 'line', dataSelection: [{ ...makeWidget().dataSelection[0], unique: true }] }), workspace)).toBe(true);
  });

  it('shows the controls of a widget with several datasets or distinct values, locked with the reason', () => {
    const widget = makeAuditsWidget();
    const severalDatasets = { ...widget, dataSelection: [...widget.dataSelection, ...widget.dataSelection] };
    const distinct = makeAuditsWidget({}, { unique: true });

    expect(isWidgetBreakdownConfigurable(widget, workspace)).toBe(true);
    expect(getWidgetBreakdownLockReason(widget)).toBeUndefined();
    expect(isWidgetBreakdownConfigurable(severalDatasets, workspace)).toBe(true);
    expect(getWidgetBreakdownLockReason(severalDatasets)).toEqual('several-datasets');
    expect(isWidgetBreakdownConfigurable(distinct, workspace)).toBe(true);
    expect(getWidgetBreakdownLockReason(distinct)).toEqual('distinct-values');
    expect(isWidgetBreakdownConfigurable(makeAuditsWidget({ type: 'donut' }), workspace)).toBe(false);
    expect(isWidgetBreakdownConfigurable(makeAuditsWidget(), { kind: 'custom-view', customViewTargetEntityType: 'Report' })).toBe(true);
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

  it('names the values of the type fields of the logs after the entity types', () => {
    expect(isBreakdownTypeField('entity_type')).toBe(true);
    expect(isBreakdownTypeField('context_data.entity_type')).toBe(true);
    expect(isBreakdownTypeField('event_scope')).toBe(false);
    expect(isBreakdownTypeField(null)).toBe(false);
  });
});
