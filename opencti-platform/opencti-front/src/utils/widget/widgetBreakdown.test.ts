import { describe, expect, it } from 'vitest';
import type { Widget, WidgetHost, WidgetPerspective } from './widget';
import { dayStartDate, daysAgo, monthsAgo } from '../Time';
import type { FilterDefinition } from '../hooks/useAuth';
import type { FilterGroup } from '../filters/filtersHelpers-types';
import type { DashboardVariable } from '../../components/dashboard/dashboard-types';
import {
  applyBreakdownCompatibility,
  BREAKDOWN_LIMIT_OPTIONS,
  type BreakdownFieldsRequest,
  canWidgetBreakDown,
  clearBreakdown,
  getBreakdownDefaultStartDate,
  getBreakdownEditorState,
  getBreakdownEntityTypes,
  getBreakdownFieldOptions,
  getBreakdownFieldsRequest,
  getBreakdownLimitOptions,
  getWidgetBreakdownLimit,
  getWidgetBreakdownOrder,
  getWidgetBreakdownOther,
  getWidgetBreakdownState,
  hasWidgetBreakdown,
  isBreakdownTypeField,
  isWidgetBreakdownActive,
  resolveBreakdownTypeVariables,
} from './widgetBreakdown';

const workspace = { kind: 'workspace' } as const;
const fintelTemplate = { kind: 'fintelTemplate' as const, fintelWidgets: [], fintelEntityType: 'Report', fintelEditorValue: '' };

const definition = (filterKey: string, type: string, label: string, subEntityTypes: string[]): FilterDefinition => ({
  filterKey, type, label, multiple: true, subEntityTypes, elementsForFilterValuesSearch: [],
});

// The fields the API offers for the requests of these tests (timeSeriesBreakdownFields), in its order
const AUDITS_API_FIELDS = ['event_type', 'event_scope', 'user_id', 'group_ids', 'organization_ids', 'entity_type', 'context_data.entity_type'];
const API_FIELDS: Record<string, string[]> = {
  'entities:': ['createdBy', 'objectLabel', 'objectMarking', 'creator_id', 'entity_type'],
  'entities:Report': ['createdBy', 'objectLabel', 'objectMarking', 'objectAssignee', 'objectParticipant', 'creator_id', 'x_opencti_closing_reason', 'report_types'],
  'entities:Malware': ['createdBy', 'objectLabel', 'objectMarking', 'objectAssignee', 'creator_id', 'malware_types'],
  'entities:Malware,Report': ['createdBy', 'objectLabel', 'objectMarking', 'creator_id', 'entity_type'],
  'relationships:': ['createdBy', 'objectLabel', 'objectMarking', 'creator_id', 'fromTypes', 'toTypes', 'relationship_type'],
  'relationships:targets': ['createdBy', 'objectLabel', 'objectMarking', 'creator_id', 'fromTypes', 'toTypes'],
  'audits:': AUDITS_API_FIELDS,
};
const readApiFields = (request: BreakdownFieldsRequest) => API_FIELDS[`${request.perspective}:${request.types.join(',')}`] ?? [];

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

describe('isWidgetBreakdownActive', () => {
  it('renders the breakdown of a widget that has a field and can be broken down, in the dashboards and custom views', () => {
    ['vertical-bar', 'line', 'area', 'heatmap'].forEach((type) => {
      expect(isWidgetBreakdownActive(makeWidget({ type }), workspace)).toBe(true);
      expect(isWidgetBreakdownActive(makeRelationshipsWidget({ type }), workspace)).toBe(true);
    });
    expect(isWidgetBreakdownActive(makeWidget(), { kind: 'custom-view', customViewTargetEntityType: 'Report' })).toBe(true);
  });

  it('needs a breakdown field, and a widget that can be broken down', () => {
    expect(isWidgetBreakdownActive(makeWidget({ parameters: { breakdownBy: null } }), workspace)).toBe(false);
    expect(isWidgetBreakdownActive(makeWidget({ type: 'donut' }), workspace)).toBe(false);
    expect(isWidgetBreakdownActive(makeWidget({}, ['DraftWorkspace']), workspace)).toBe(false);
    const widget = makeWidget();
    expect(isWidgetBreakdownActive({ ...widget, dataSelection: [...widget.dataSelection, ...widget.dataSelection] }, workspace)).toBe(false);
  });

  it('needs a host that breaks its widgets down, while still knowing the widget is broken down', () => {
    // A fintel template writes its widgets in a document
    expect(isWidgetBreakdownActive(makeWidget(), fintelTemplate)).toBe(false);
    expect(isWidgetBreakdownActive(makeWidget(), undefined)).toBe(false);
    // ...but the widget is broken down, to be refused elsewhere
    expect(hasWidgetBreakdown(makeWidget())).toBe(true);
    expect(hasWidgetBreakdown(makeWidget({ parameters: { breakdownBy: null } }))).toBe(false);
    expect(hasWidgetBreakdown(makeWidget({ type: 'donut' }))).toBe(false);
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
  const schema = new Map<string, Map<string, FilterDefinition>>([
    ['Report', new Map([
      ['createdBy', definition('createdBy', 'id', 'Author', ['Report'])],
      ['objectLabel', definition('objectLabel', 'id', 'Label', ['Report'])],
      ['report_types', definition('report_types', 'vocabulary', 'Report types', ['Report'])],
      ['x_opencti_closing_reason', definition('x_opencti_closing_reason', 'string', 'Closing reason', ['Report'])],
    ])],
    ['stix-relationship', new Map([
      ['objectMarking', definition('objectMarking', 'id', 'Marking', ['stix-relationship', 'targets'])],
      ['creator_id', definition('creator_id', 'id', 'Creators', ['stix-relationship', 'targets'])],
    ])],
  ]);
  const options = (keys: string[], perspective: WidgetPerspective = 'entities', translate?: (label: string) => string) => {
    return getBreakdownFieldOptions(schema, keys, perspective, translate);
  };

  it('labels the fields the API offers after their filter, whatever the fields the schema alone would tell', () => {
    // The closing reason is not a vocabulary for the filters, but the API accepts it for the reports
    expect(options(['report_types', 'x_opencti_closing_reason', 'createdBy'])).toEqual([
      { key: 'createdBy', label: 'Author' },
      { key: 'x_opencti_closing_reason', label: 'Closing reason' },
      { key: 'report_types', label: 'Report types' },
    ]);
    // A field the schema does not know is labelled with its key
    expect(options(['x_unknown'])).toEqual([{ key: 'x_unknown', label: 'x_unknown' }]);
  });

  it('labels the fields of the perspective after the perspective', () => {
    expect(options(['entity_type', 'objectLabel'])).toEqual([
      { key: 'entity_type', label: 'Entity type' },
      { key: 'objectLabel', label: 'Label' },
    ]);
    expect(options(['toTypes', 'relationship_type', 'fromTypes', 'objectMarking'], 'relationships').map(({ label }) => label))
      .toEqual(['Marking', 'Relationship type', 'Source type', 'Target type']);
  });

  it('orders the fields by their translated label, and keeps the labels to translate where shown', () => {
    const french: Record<string, string> = {
      Creators: 'Créateurs',
      Marking: 'Marquage',
      'Relationship type': 'Type de relation',
      'Source type': 'Type de source',
      'Target type': 'Type de cible',
    };
    const translate = (label: string) => french[label] ?? label;
    const relationshipOptions = options(['objectMarking', 'creator_id', 'fromTypes', 'toTypes', 'relationship_type'], 'relationships', translate);
    expect(relationshipOptions.map(({ label }) => translate(label))).toEqual(['Créateurs', 'Marquage', 'Type de cible', 'Type de relation', 'Type de source']);
    expect(relationshipOptions.map(({ label }) => label)).toContain('Target type');
  });

  it('labels the fields of the logs, and keeps them in the order of the API whatever the language', () => {
    const reversed = (label: string) => label.split('').reverse().join('');
    const auditsOptions = options(AUDITS_API_FIELDS, 'audits', reversed);
    expect(auditsOptions.map(({ key }) => key)).toEqual(AUDITS_API_FIELDS);
    expect(auditsOptions.map(({ label }) => label)).toEqual(['Event type', 'Event_scope', 'User', 'Group', 'Organization', 'Entity_type', 'Type of related entity']);
    // Their own labels first: the entity type of the logs is the one of History or Activity
    expect(options(['entity_type'], 'audits')).toEqual([{ key: 'entity_type', label: 'Entity_type' }]);
  });
});

describe('getBreakdownFieldsRequest', () => {
  const resolved = { resolution: 'resolved' } as const;
  const requestOf = (widget: Widget, savedFilter: Parameters<typeof getBreakdownFieldsRequest>[0]['savedFilter'] = resolved, variables?: DashboardVariable[], host: WidgetHost = workspace) => {
    return getBreakdownFieldsRequest({ widget, host, savedFilter, variables });
  };
  const ofTypes = (types: string[], key = 'entity_type') => ({
    mode: 'and', filters: [{ key, values: types, operator: 'eq', mode: 'or' }], filterGroups: [],
  } as FilterGroup);
  // A dataset read from a saved filter holds no filters of its own
  const savedFilterWidget = { ...makeWidget(), dataSelection: [{ filters_id: 'saved-filter', filters: undefined }] } as unknown as Widget;

  it('asks the fields of the types the dataset is restricted to, sorted to ask the same types once whatever their order', () => {
    expect(requestOf(makeWidget())).toEqual({ perspective: 'entities', types: ['Report'] });
    expect(requestOf(makeWidget({}, ['Report', 'Malware']))).toEqual({ perspective: 'entities', types: ['Malware', 'Report'] });
    expect(requestOf(makeWidget({}, ['Malware', 'Report']))).toEqual({ perspective: 'entities', types: ['Malware', 'Report'] });
    expect(requestOf(makeRelationshipsWidget())).toEqual({ perspective: 'relationships', types: ['targets'] });
    expect(requestOf(makeRelationshipsWidget({}, ['uses', 'targets']))).toEqual({ perspective: 'relationships', types: ['targets', 'uses'] });
  });

  it('asks the fields of any type of the perspective without type filter, and of the logs whatever their filters', () => {
    expect(requestOf({ ...makeWidget(), dataSelection: [{ filters: undefined }] } as unknown as Widget)).toEqual({ perspective: 'entities', types: [] });
    // "type = Report OR label = A" can also return other types
    const orFilters = { mode: 'or', filters: [...ofTypes(['Report']).filters, { key: 'objectLabel', values: ['label-id'], operator: 'eq', mode: 'or' }], filterGroups: [] };
    expect(requestOf({ ...makeWidget(), dataSelection: [{ filters: orFilters }] } as unknown as Widget)).toEqual({ perspective: 'entities', types: [] });
    const logs = { ...makeWidget({ type: 'line', perspective: 'audits' }), dataSelection: [{ filters: ofTypes(['History']) }] } as unknown as Widget;
    expect(requestOf(logs)).toEqual({ perspective: 'audits', types: [] });
  });

  it('asks the fields of the types a type variable allows, of any type for a variable that may hold any', () => {
    const VARIABLE_ID = '6f1c3f0e-2b7a-4c1e-9d3a-0a1b2c3d4e5f';
    const typeVariable = (restriction: DashboardVariable['restriction']): DashboardVariable => ({
      id: VARIABLE_ID, name: 'type', type: 'entityType', defaultValue: null, restriction,
    });
    const widget = makeWidget({}, [`$var:${VARIABLE_ID}`]);
    expect(requestOf(widget, resolved, [typeVariable({ mode: 'selection', values: ['Report', 'Malware'] })]))
      .toEqual({ perspective: 'entities', types: ['Malware', 'Report'] });
    expect(requestOf(widget, resolved, [typeVariable({ mode: 'none' })])).toEqual({ perspective: 'entities', types: [] });
  });

  it('asks nothing until the saved filter is read, and then the fields of its content', () => {
    expect(requestOf(savedFilterWidget, { resolution: 'loading' })).toBeNull();
    expect(requestOf(savedFilterWidget, { resolution: 'resolved', filters: ofTypes(['Malware']) })).toEqual({ perspective: 'entities', types: ['Malware'] });
    // Its types unknown, the fields of any type
    expect(requestOf(savedFilterWidget, { resolution: 'failed', filters: null })).toEqual({ perspective: 'entities', types: [] });
  });

  it('asks nothing for a widget whose breakdown is hidden, like the draft workspaces of a saved filter', () => {
    expect(requestOf(savedFilterWidget, { resolution: 'resolved', filters: ofTypes(['DraftWorkspace']) })).toBeNull();
    expect(requestOf(makeWidget({}, ['DraftWorkspace']))).toBeNull();
    expect(requestOf(makeWidget({ type: 'donut' }))).toBeNull();
    expect(requestOf(makeWidget({ perspective: null }))).toBeNull();
    expect(requestOf(makeWidget(), resolved, undefined, fintelTemplate)).toBeNull();
    // Several datasets: the controls are shown, disabled, with the fields of the first one
    const widget = makeWidget();
    expect(requestOf({ ...widget, dataSelection: [...widget.dataSelection, ...widget.dataSelection] })).toEqual({ perspective: 'entities', types: ['Report'] });
  });
});

describe('resolveBreakdownTypeVariables', () => {
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
});

describe('audits breakdown', () => {
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
    expect(isWidgetBreakdownActive(makeAuditsWidget(), workspace)).toBe(true);
    expect(isWidgetBreakdownActive(makeAuditsWidget({ type: 'line' }, { unique: true }), workspace)).toBe(false);
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

  it('offers the fields the API accepts for the logs, in its order, and keeps one of them only', () => {
    const stateOf = (widget: Widget) => {
      const request = getBreakdownFieldsRequest({ widget, host: workspace, savedFilter: { resolution: 'resolved' } });
      const reversed = (label: string) => label.split('').reverse().join('');
      return getWidgetBreakdownState({
        filterKeysSchema: new Map(),
        widget,
        host: workspace,
        savedFilter: { resolution: 'resolved' },
        fields: { resolution: 'resolved', keys: request ? readApiFields(request) : [] },
        translate: reversed,
      });
    };
    const state = stateOf(makeAuditsWidget());
    expect(state.fieldOptions.map(({ key }) => key)).toEqual(AUDITS_API_FIELDS);
    expect(state).toMatchObject({ field: 'event_scope', unlistedField: null });
    // The context entity id, the free texts and the entities fields are not offered: not kept
    ['context_data.id', 'context_data.message', 'creator_id', 'objectLabel'].forEach((breakdownBy) => {
      expect(stateOf(makeAuditsWidget({ parameters: { breakdownBy } })).field).toBeNull();
    });
  });

  it('names the values of the type fields of the logs after the entity types', () => {
    expect(isBreakdownTypeField('entity_type')).toBe(true);
    expect(isBreakdownTypeField('context_data.entity_type')).toBe(true);
    expect(isBreakdownTypeField('event_scope')).toBe(false);
    expect(isBreakdownTypeField(null)).toBe(false);
  });
});

describe('getWidgetBreakdownState', () => {
  const schema = new Map<string, Map<string, FilterDefinition>>([
    ['Report', new Map([
      ['createdBy', definition('createdBy', 'id', 'Author', ['Report'])],
      ['objectLabel', definition('objectLabel', 'id', 'Label', ['Report'])],
      ['objectMarking', definition('objectMarking', 'id', 'Marking', ['Report'])],
      ['objectAssignee', definition('objectAssignee', 'id', 'Assignees', ['Report'])],
      ['objectParticipant', definition('objectParticipant', 'id', 'Participants', ['Report'])],
      ['creator_id', definition('creator_id', 'id', 'Creators', ['Report'])],
      ['report_types', definition('report_types', 'vocabulary', 'Report types', ['Report'])],
      ['x_opencti_closing_reason', definition('x_opencti_closing_reason', 'string', 'Closing reason', ['Report'])],
    ])],
    ['Malware', new Map([
      ['createdBy', definition('createdBy', 'id', 'Author', ['Malware'])],
      ['malware_types', definition('malware_types', 'vocabulary', 'Malware types', ['Malware'])],
    ])],
    ['stix-relationship', new Map([['objectMarking', definition('objectMarking', 'id', 'Marking', ['stix-relationship', 'targets'])]])],
  ]);
  const ofTypes = (types: string[], key = 'entity_type') => ({
    mode: 'and', filters: [{ key, values: types, operator: 'eq', mode: 'or' }], filterGroups: [],
  } as FilterGroup);
  // A dataset read from a saved filter holds no filters of its own
  const savedFilterWidget = (breakdownBy: string) => ({
    ...makeWidget({ parameters: { breakdownBy } }),
    dataSelection: [{ filters_id: 'saved-filter', filters: undefined }],
  } as unknown as Widget);
  type StateArguments = Parameters<typeof getWidgetBreakdownState>[0];
  const resolved = { resolution: 'resolved' } as const;
  const loadingFields = { resolution: 'loading' } as const;
  const failedFields = { resolution: 'failed', keys: null } as const;
  // The fields are the ones the API offers for the dataset, read once asked, unless given
  const stateOf = (
    widget: Widget,
    savedFilter: StateArguments['savedFilter'] = resolved,
    { host = workspace, variables, fields }: { host?: WidgetHost; variables?: DashboardVariable[]; fields?: StateArguments['fields'] } = {},
  ) => {
    const request = getBreakdownFieldsRequest({ widget, host, savedFilter, variables });
    const readFields = request ? { resolution: 'resolved', keys: readApiFields(request) } as const : loadingFields;
    return getWidgetBreakdownState({ filterKeysSchema: schema, widget, host, savedFilter, fields: fields ?? readFields });
  };
  const keys = (state: { fieldOptions: { key: string }[] }) => state.fieldOptions.map(({ key }) => key);

  it('offers the fields the API offers for the dataset, labelled and ordered, and keeps a field among them', () => {
    const state = stateOf(makeWidget({ parameters: { breakdownBy: 'report_types' } }));
    expect(state).toMatchObject({ editorState: 'editable', resolution: 'resolved', savedFilterResolution: 'resolved', field: 'report_types', unlistedField: null });
    expect(state.fieldOptions.map(({ label }) => label))
      .toEqual(['Assignees', 'Author', 'Closing reason', 'Creators', 'Label', 'Marking', 'Participants', 'Report types']);
    expect(keys(state)).toEqual(['objectAssignee', 'createdBy', 'x_opencti_closing_reason', 'creator_id', 'objectLabel', 'objectMarking', 'objectParticipant', 'report_types']);
    expect(stateOf(makeWidget({ parameters: {} })).field).toBeNull();
  });

  it('keeps a field the API accepts which the filters do not tell, like the closing reason of the reports', () => {
    expect(stateOf(makeWidget({ parameters: { breakdownBy: 'x_opencti_closing_reason' } }))).toMatchObject({
      field: 'x_opencti_closing_reason',
      unlistedField: null,
    });
    expect(stateOf(makeWidget({ parameters: { breakdownBy: 'x_opencti_closing_reason' } }, ['Malware'])).field).toBeNull();
  });

  it('does not keep a field the API does not offer for the dataset types, to drop it on submit', () => {
    const state = stateOf(makeWidget({ parameters: { breakdownBy: 'report_types' } }, ['Malware']));
    expect(state).toMatchObject({ editorState: 'editable', field: null, unlistedField: null });
    expect(keys(state)).toContain('malware_types');
    expect(keys(state)).not.toContain('report_types');
  });

  it('keeps only a field the API lists, not the type of a dataset of a single type, which makes a single series', () => {
    expect(stateOf(makeWidget({ parameters: { breakdownBy: 'entity_type' } }))).toMatchObject({ field: null, unlistedField: null });
    // A type variable allowing a single type
    const VARIABLE_ID = '6f1c3f0e-2b7a-4c1e-9d3a-0a1b2c3d4e5f';
    const variable: DashboardVariable = { id: VARIABLE_ID, name: 'type', type: 'entityType', defaultValue: null, restriction: { mode: 'selection', values: ['Report'] } };
    const byVariable = makeWidget({ parameters: { breakdownBy: 'entity_type' } }, [`$var:${VARIABLE_ID}`]);
    expect(stateOf(byVariable, resolved, { variables: [variable] })).toMatchObject({ field: null, unlistedField: null });
    // ...whose fields are kept, which a variable that may hold any type does not have
    const reportTypesByVariable = { ...byVariable, parameters: { breakdownBy: 'report_types' } };
    expect(stateOf(reportTypesByVariable, resolved, { variables: [variable] }).field).toEqual('report_types');
    expect(stateOf(reportTypesByVariable, resolved, { variables: [{ ...variable, restriction: { mode: 'none' } }] }).field).toBeNull();
    // A single relationship type
    const targets = makeRelationshipsWidget({ parameters: { breakdownBy: 'relationship_type' } });
    expect(stateOf(targets)).toMatchObject({ field: null, unlistedField: null });
    // Listed with several types: kept among the options
    expect(stateOf(makeWidget({ parameters: { breakdownBy: 'entity_type' } }, ['Report', 'Malware']))).toMatchObject({ field: 'entity_type', unlistedField: null });
    // Kept while the fields of the dataset are unknown, as any field
    expect(stateOf(makeWidget({ parameters: { breakdownBy: 'entity_type' } }), resolved, { fields: loadingFields }))
      .toMatchObject({ field: 'entity_type', unlistedField: { key: 'entity_type', label: 'Entity type' } });
  });

  it('keeps the field while the saved filter is read, offering no other, and lists it apart', () => {
    const loading = stateOf(savedFilterWidget('report_types'), { resolution: 'loading' });
    expect(loading).toEqual({
      editorState: 'editable',
      fieldOptions: [],
      resolution: 'loading',
      savedFilterResolution: 'loading',
      field: 'report_types',
      unlistedField: { key: 'report_types', label: 'Report types' },
    });
    // Unknown to the schema, labelled with its key
    expect(stateOf(savedFilterWidget('x_unknown'), { resolution: 'loading' }).unlistedField).toEqual({ key: 'x_unknown', label: 'x_unknown' });
  });

  it('keeps the field while the fields of the dataset are read, offering no other', () => {
    expect(stateOf(makeWidget({ parameters: { breakdownBy: 'report_types' } }, ['Malware']), resolved, { fields: loadingFields })).toEqual({
      editorState: 'editable',
      fieldOptions: [],
      resolution: 'loading',
      savedFilterResolution: 'resolved',
      field: 'report_types',
      unlistedField: { key: 'report_types', label: 'Report types' },
    });
    // Read after the saved filter
    const savedFilter = { resolution: 'resolved', filters: ofTypes(['Malware']) } as const;
    expect(stateOf(savedFilterWidget('report_types'), savedFilter, { fields: loadingFields })).toMatchObject({ resolution: 'loading', field: 'report_types' });
  });

  it('keeps the field when the fields of the dataset cannot be read, offering no other, without blaming the saved filter', () => {
    expect(stateOf(makeWidget({ parameters: { breakdownBy: 'report_types' } }, ['Malware']), resolved, { fields: failedFields })).toEqual({
      editorState: 'editable',
      fieldOptions: [],
      resolution: 'failed',
      savedFilterResolution: 'resolved',
      field: 'report_types',
      unlistedField: { key: 'report_types', label: 'Report types' },
    });
    expect(stateOf(makeWidget({ parameters: {} }), resolved, { fields: failedFields })).toMatchObject({ resolution: 'failed', field: null, fieldOptions: [] });
  });

  it('keeps the field of a saved filter that cannot be read, offering the fields of any type', () => {
    const unreadable = { resolution: 'failed', filters: null } as const;
    const state = stateOf(savedFilterWidget('report_types'), unreadable);
    expect(state).toMatchObject({
      resolution: 'failed',
      savedFilterResolution: 'failed',
      field: 'report_types',
      unlistedField: { key: 'report_types', label: 'Report types' },
    });
    expect(keys(state)).toEqual(expect.arrayContaining(['createdBy', 'entity_type']));
    // Still loading while these fields are read
    expect(stateOf(savedFilterWidget('report_types'), unreadable, { fields: loadingFields })).toMatchObject({ resolution: 'loading', savedFilterResolution: 'failed' });
    // Offered whatever the types: not listed apart
    expect(stateOf(savedFilterWidget('createdBy'), unreadable)).toMatchObject({ field: 'createdBy', unlistedField: null });
  });

  it('reads the fields of the content of the saved filter once read', () => {
    const reports = stateOf(savedFilterWidget('report_types'), { resolution: 'resolved', filters: ofTypes(['Report']) });
    expect(reports).toMatchObject({ field: 'report_types', unlistedField: null });
    expect(keys(reports)).toContain('report_types');
    expect(stateOf(savedFilterWidget('report_types'), { resolution: 'resolved', filters: ofTypes(['Malware']) }).field).toBeNull();
  });

  it('hides the breakdown of draft workspaces, read on the content of the saved filter', () => {
    const drafts = { resolution: 'resolved', filters: ofTypes(['DraftWorkspace']) } as const;
    expect(stateOf(savedFilterWidget('creator_id'), drafts)).toEqual({
      editorState: 'hidden', fieldOptions: [], resolution: 'resolved', savedFilterResolution: 'resolved', field: null, unlistedField: null,
    });
    expect(stateOf(makeWidget({ parameters: { breakdownBy: 'creator_id' } }, ['DraftWorkspace'])).editorState).toEqual('hidden');
    // Unknown until the saved filter is read
    expect(stateOf(savedFilterWidget('creator_id'), { resolution: 'loading' }).editorState).toEqual('editable');
  });

  it('shows the controls of several datasets or distinct values, without keeping the field', () => {
    const widget = makeWidget({ parameters: { breakdownBy: 'report_types' } });
    const severalDatasets = stateOf({ ...widget, dataSelection: [...widget.dataSelection, ...widget.dataSelection] });
    expect(severalDatasets).toMatchObject({ editorState: 'several-datasets', field: null, unlistedField: null });
    expect(keys(severalDatasets)).toContain('report_types');
    const distinct = {
      ...makeWidget({ type: 'line', perspective: 'audits', parameters: { breakdownBy: 'event_type' } }),
      dataSelection: [{ filters: ofTypes([]), unique: true }],
    } as unknown as Widget;
    expect(stateOf(distinct)).toMatchObject({ editorState: 'distinct-values', field: null });
  });

  it('keeps the breakdown of every time series visualization of the dashboards and custom views', () => {
    ['line', 'area', 'vertical-bar', 'heatmap'].forEach((type) => {
      expect(stateOf(makeWidget({ type, parameters: { breakdownBy: 'report_types' } })).field).toEqual('report_types');
      expect(stateOf(makeRelationshipsWidget({ type, parameters: { breakdownBy: 'toTypes' } })).field).toEqual('toTypes');
    });
    const customView = { kind: 'custom-view' as const, customViewTargetEntityType: 'Report' };
    expect(stateOf(makeWidget({ parameters: { breakdownBy: 'report_types' } }), resolved, { host: customView }).field).toEqual('report_types');
  });

  it('hides the breakdown of the widgets that cannot be broken down', () => {
    const hidden = (widget: Widget, host: WidgetHost = workspace) => stateOf(widget, resolved, { host }).editorState;
    expect(hidden(makeWidget({ type: 'donut' }))).toEqual('hidden');
    expect(hidden(makeWidget({ perspective: null }))).toEqual('hidden');
    expect(hidden(makeWidget(), fintelTemplate)).toEqual('hidden');
    // A relationships widget left with an entities dataset cannot be broken down as relationships
    const relationships = makeRelationshipsWidget();
    expect(hidden({ ...relationships, dataSelection: [{ ...relationships.dataSelection[0], perspective: 'entities' }] })).toEqual('hidden');
    expect(stateOf(makeWidget({ type: 'donut' })).field).toBeNull();
  });
});

describe('applyBreakdownCompatibility', () => {
  const widget = {
    type: 'line',
    parameters: { title: 'Reports', breakdownBy: 'report_types', breakdownLimit: 20, breakdownOrder: 'asc' as const, breakdownOther: true },
  };

  it('drops the breakdown and its settings when the editor does not keep its field', () => {
    expect(applyBreakdownCompatibility(widget, { field: null }).parameters).toEqual({
      title: 'Reports', breakdownBy: null, breakdownLimit: null, breakdownOrder: null, breakdownOther: null,
    });
  });

  it('returns the widget untouched when its field is kept, or without breakdown', () => {
    expect(applyBreakdownCompatibility(widget, { field: 'report_types' })).toBe(widget);
    // No breakdown settings written on a widget that never had one
    const donut = { type: 'donut', parameters: { title: 'Donut' } };
    expect(applyBreakdownCompatibility(donut, { field: null })).toBe(donut);
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
