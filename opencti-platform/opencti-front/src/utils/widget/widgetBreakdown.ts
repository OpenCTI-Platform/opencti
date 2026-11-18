import type { Widget, WidgetHost, WidgetParameters, WidgetPerspective } from './widget';
import { getCurrentCategory } from './widgetUtils';
import { isDraftWorkspaceFilterGroup } from '../filters/filtersUtils';
import type { FilterGroup } from '../filters/filtersHelpers-types';
import type { FilterDefinition } from '../hooks/useAuth';
import { dayStartDate, daysAgo, monthsAgo, parse } from '../Time';
import type { DashboardVariable } from '../../components/dashboard/dashboard-types';
import { parseVariableToken } from '../../components/dashboard/dashboardVariablesResolution';

export const BREAKDOWN_LIMIT_OPTIONS = [5, 10, 20, 50];
export const DEFAULT_BREAKDOWN_LIMIT = 10;

// Draft workspaces cannot be broken down: read on the filters of the widget, or on the content of its saved filter
const isDraftWorkspaceDataset = (dataSelection: Widget['dataSelection']) => isDraftWorkspaceFilterGroup(dataSelection[0]?.filters);

// Labels of the fields of the history and activity logs: the API says which ones a breakdown accepts, and their order
const AUDITS_BREAKDOWN_LABELS = new Map([
  ['event_type', 'Event type'],
  ['event_scope', 'Event_scope'],
  ['user_id', 'User'],
  ['group_ids', 'Group'],
  ['organization_ids', 'Organization'],
  ['entity_type', 'Entity_type'],
  ['context_data.entity_type', 'Type of related entity'],
]);
// Fields of the logs whose values are entity types (History or Activity, the type of the related entity)
const AUDITS_TYPE_FIELDS = ['entity_type', 'context_data.entity_type'];

export type BreakdownField = { key: string; label: string };
interface BreakdownPerspective {
  // Filter key restricting the types of the dataset
  typeFilterKey: string;
  // The type itself, labelled here: the API lists it when it makes several series
  typeField: BreakdownField;
  // Fields of the perspective that are not filters of the schema, labelled here
  fields: BreakdownField[];
}
const BREAKDOWN_PERSPECTIVES: Partial<Record<WidgetPerspective, BreakdownPerspective>> = {
  entities: {
    typeFilterKey: 'entity_type',
    typeField: { key: 'entity_type', label: 'Entity type' },
    fields: [],
  },
  relationships: {
    typeFilterKey: 'relationship_type',
    typeField: { key: 'relationship_type', label: 'Relationship type' },
    // Each relationship has a single source and a single target, among a bounded number of types
    fields: [{ key: 'fromTypes', label: 'Source type' }, { key: 'toTypes', label: 'Target type' }],
  },
};
const getBreakdownPerspective = (perspective?: WidgetPerspective | null) => {
  return perspective ? BREAKDOWN_PERSPECTIVES[perspective] : undefined;
};
// Perspectives with a breakdown API: the schema-based ones above, and the audits with their own fields
type BreakdownWidgetPerspective = 'entities' | 'relationships' | 'audits';
const isBreakdownPerspective = (perspective?: WidgetPerspective | null): perspective is BreakdownWidgetPerspective => {
  return perspective === 'audits' || !!getBreakdownPerspective(perspective);
};

/**
 * Fields the series are labelled with a type: an entity type, or a relationship type.
 */
export const isBreakdownTypeField = (field?: string | null) => {
  return (!!field && AUDITS_TYPE_FIELDS.includes(field)) || Object.values(BREAKDOWN_PERSPECTIVES).some((perspective) => (
    perspective.typeField.key === field || perspective.fields.some(({ key }) => key === field)
  ));
};

/**
 * The breakdown field is a filter key: a value is set when a field is chosen.
 */
export const isBreakdownField = (value?: string | null): value is string => {
  return !!value;
};

/**
 * Types every element of the dataset belongs to, read from a top level "entity type = ..." filter,
 * or "relationship type = ..." for relationships. Empty when the filters do not restrict the type for sure.
 */
export const getBreakdownEntityTypes = (filters?: FilterGroup | null, perspective: WidgetPerspective = 'entities'): string[] => {
  const typeFilterKey = getBreakdownPerspective(perspective)?.typeFilterKey;
  if (!filters || !typeFilterKey) return [];
  const isRestrictingGroup = filters.mode === 'and' || filters.filters.length + filters.filterGroups.length === 1;
  const typeFilter = filters.filters.find((filter) => filter.key === typeFilterKey);
  // Several types in "and" only keep the elements of every type, while a single one restricts the type whatever the mode
  const isTypeIntersection = typeFilter?.mode === 'and' && typeFilter.values.length > 1;
  if (!isRestrictingGroup || !typeFilter || (typeFilter.operator && typeFilter.operator !== 'eq') || isTypeIntersection) {
    return [];
  }
  return typeFilter.values.filter((value): value is string => typeof value === 'string');
};

/**
 * Types the dataset can hold whatever the values of its dashboard variables: a type variable stands for
 * the types it allows. Empty, like without a type filter, when a variable may hold any type.
 */
export const resolveBreakdownTypeVariables = (types: string[], variables?: DashboardVariable[]): string[] => {
  const resolvedTypes = new Set<string>();
  for (const type of types) {
    const variableId = parseVariableToken(type);
    const variable = variableId ? variables?.find(({ id }) => id === variableId) : undefined;
    if (!variableId) {
      resolvedTypes.add(type);
    } else if (variable?.type === 'entityType' && variable.restriction.mode === 'selection' && variable.restriction.values.length > 0) {
      variable.restriction.values.forEach((value) => resolvedTypes.add(value));
    } else {
      return [];
    }
  }
  return Array.from(resolvedTypes);
};

export const getWidgetBreakdownLimit = (parameters?: WidgetParameters | null) => {
  return parameters?.breakdownLimit ?? DEFAULT_BREAKDOWN_LIMIT;
};

/**
 * Numbers of series offered, with the one of the widget among them: the API accepts any from 1 to 50,
 * so an imported widget, or one written through the API, can hold another.
 */
export const getBreakdownLimitOptions = (parameters?: WidgetParameters | null) => {
  const limit = getWidgetBreakdownLimit(parameters);
  return BREAKDOWN_LIMIT_OPTIONS.includes(limit) ? BREAKDOWN_LIMIT_OPTIONS : [...BREAKDOWN_LIMIT_OPTIONS, limit].sort((a, b) => a - b);
};

export const getWidgetBreakdownOrder = (parameters?: WidgetParameters | null): 'asc' | 'desc' => {
  return parameters?.breakdownOrder === 'asc' ? 'asc' : 'desc';
};

export const getWidgetBreakdownOther = (parameters?: WidgetParameters | null) => {
  return parameters?.breakdownOther ?? false;
};

/**
 * Start date used when the dashboard sets none: a daily breakdown over the default 12 months
 * would draw too many bars, so it only looks back 30 days. It looks back from the `endDate` of the
 * dashboard when it sets one, from today otherwise: an end date in the past keeps a period to draw.
 */
export const getBreakdownDefaultStartDate = (interval: string, endDate?: string | null) => {
  if (!endDate) {
    return interval === 'day' ? daysAgo(30) : monthsAgo(12);
  }
  return interval === 'day' ? daysAgo(30, endDate) : parse(dayStartDate(endDate)).subtract(12, 'months').format();
};

type BreakdownWidget = Pick<Widget, 'type' | 'perspective' | 'dataSelection'>;
type ConfiguredWidget = { parameters?: WidgetParameters | null };

// Audits lines and areas can count the distinct values of an attribute instead of the events
const AUDITS_DISTINCT_COUNT_TYPES = ['line', 'area'];
const isCountingDistinctValues = (widget: BreakdownWidget) => {
  return widget.perspective === 'audits'
    && AUDITS_DISTINCT_COUNT_TYPES.includes(widget.type)
    && widget.dataSelection.some((selection) => selection.unique === true);
};

// Hosts whose widgets can be broken down: the dashboards, and the custom views, whose widgets read the
// platform data the same way, around their entity. A fintel template writes its widgets in a document.
const BREAKDOWN_HOST_KINDS: WidgetHost['kind'][] = ['workspace', 'custom-view'];

/**
 * Whether the widget can be broken down: a breakdown expands the single dataset of a time series widget,
 * counting its entities, relationships or events, outside the drafts. A relationships widget can also hold
 * entities datasets: they cannot be broken down as relationships. With a `host`, whether it breaks its
 * widgets down too (the workspace dashboards and the custom views); without one, the widget alone decides.
 */
export const canWidgetBreakDown = (widget: BreakdownWidget, host?: WidgetHost) => {
  const [dataset] = widget.dataSelection;
  return (!host || BREAKDOWN_HOST_KINDS.includes(host.kind))
    && isBreakdownPerspective(widget.perspective)
    && getCurrentCategory(widget.type) === 'timeseries'
    && widget.dataSelection.length === 1
    && (dataset.perspective ?? widget.perspective) === widget.perspective
    && !isDraftWorkspaceDataset(widget.dataSelection)
    && !isCountingDistinctValues(widget);
};

/**
 * Whether the widget is configured with a breakdown, whatever renders it: its field is set and the widget
 * can be broken down.
 */
export const hasWidgetBreakdown = (widget: BreakdownWidget & ConfiguredWidget) => {
  return isBreakdownField(widget.parameters?.breakdownBy) && canWidgetBreakDown(widget);
};

/**
 * Whether the widget must be rendered as a breakdown: configured with one, in a `host` that breaks its widgets down.
 */
export const isWidgetBreakdownActive = (widget: BreakdownWidget & ConfiguredWidget, host?: WidgetHost) => {
  return !!host && isBreakdownField(widget.parameters?.breakdownBy) && canWidgetBreakDown(widget, host);
};

/**
 * How the editor shows the breakdown: 'hidden' when the widget could not be broken down even reduced to its
 * first dataset counting every event, 'editable' when it can be, disabled otherwise, for the reason given:
 * a breakdown uses a single dataset ('several-datasets'), and counts every event ('distinct-values').
 */
export type BreakdownEditorState = 'hidden' | 'editable' | 'several-datasets' | 'distinct-values';
export const getBreakdownEditorState = (widget: BreakdownWidget, host: WidgetHost): BreakdownEditorState => {
  const [firstSelection] = widget.dataSelection;
  if (!firstSelection || !canWidgetBreakDown({ ...widget, dataSelection: [{ ...firstSelection, unique: false }] }, host)) {
    return 'hidden';
  }
  if (widget.dataSelection.length > 1) {
    return 'several-datasets';
  }
  if (isCountingDistinctValues(widget)) {
    return 'distinct-values';
  }
  return 'editable';
};

// Cleared together with the field: the settings only make sense for a broken down widget
const NO_BREAKDOWN = { breakdownBy: null, breakdownLimit: null, breakdownOrder: null, breakdownOther: null };

/**
 * The widget without breakdown: its field, and its settings with it.
 */
export const clearBreakdown = <T extends ConfiguredWidget>(widget: T): T => ({
  ...widget,
  parameters: { ...widget.parameters, ...NO_BREAKDOWN },
});

/**
 * Whether what the field of the widget is checked against is read: the saved filter of the dataset, then the fields
 * the API offers for it. Until then, or when one cannot be, the fields of the dataset are unknown. A dataset without
 * saved filter has its saved filter resolved.
 */
export type BreakdownResolution = 'resolved' | 'loading' | 'failed';

// The least resolved of the resolutions: loading while one is read, failed when one cannot be
const BREAKDOWN_RESOLUTIONS: BreakdownResolution[] = ['loading', 'failed', 'resolved'];
const combineResolutions = (...resolutions: BreakdownResolution[]) => BREAKDOWN_RESOLUTIONS.find((resolution) => resolutions.includes(resolution)) ?? 'resolved';

/**
 * The breakdown of a widget in the editor, derived once for the whole editor.
 */
export interface WidgetBreakdownState {
  // Whether the controls are shown, and why they are disabled
  editorState: BreakdownEditorState;
  // Fields offered for the dataset its query reads, ordered as their labels are shown: none until the API says which
  fieldOptions: BreakdownField[];
  // Whether the saved filter of the dataset, and then the fields offered for it, are read
  resolution: BreakdownResolution;
  // Whether the saved filter of the dataset alone is read: the editor says when it cannot be
  savedFilterResolution: BreakdownResolution;
  // Field the widget is broken down by, kept on submit: none when the widget, or its dataset, cannot be broken down by it
  field: string | null;
  // The field, when it is not among the options: kept while the fields of the dataset are unknown
  unlistedField: BreakdownField | null;
}

export const NO_BREAKDOWN_STATE: WidgetBreakdownState = {
  editorState: 'hidden',
  fieldOptions: [],
  resolution: 'resolved',
  savedFilterResolution: 'resolved',
  field: null,
  unlistedField: null,
};

type SavedFilterContent = { resolution: BreakdownResolution; filters?: FilterGroup | null };

// The widget reading the content of the saved filter of its dataset, once read
const withSavedFilter = <T extends BreakdownWidget>(widget: T, savedFilter: SavedFilterContent): T => {
  const [firstSelection, ...otherSelections] = widget.dataSelection;
  return firstSelection && savedFilter.filters
    ? { ...widget, dataSelection: [{ ...firstSelection, filters: savedFilter.filters }, ...otherSelections] }
    : widget;
};

/**
 * What the editor asks the API the fields of (fetchTimeSeriesBreakdownFields): the perspective of the dataset,
 * and the types it is restricted to, sorted, none for any type of the perspective, or for the logs.
 */
export interface BreakdownFieldsRequest {
  perspective: BreakdownWidgetPerspective;
  types: string[];
}

/**
 * The fields to ask the API for the edited widget, once the dataset its query reads is known: the content of its
 * saved filter read (`savedFilter`), and its type variables read as the types they allow, given the dashboard
 * `variables`. None while the saved filter is read, nor for a widget whose breakdown is hidden, like the ones of
 * draft workspaces. A saved filter that cannot be read leaves the types unknown: the fields of any type are asked.
 */
export const getBreakdownFieldsRequest = ({
  widget,
  host,
  savedFilter,
  variables,
}: {
  widget: BreakdownWidget;
  host: WidgetHost;
  savedFilter: SavedFilterContent;
  variables?: DashboardVariable[];
}): BreakdownFieldsRequest | null => {
  if (savedFilter.resolution === 'loading') {
    return null;
  }
  const resolvedWidget = withSavedFilter(widget, savedFilter);
  const { perspective } = resolvedWidget;
  if (getBreakdownEditorState(resolvedWidget, host) === 'hidden' || !isBreakdownPerspective(perspective)) {
    return null;
  }
  if (perspective === 'audits') {
    return { perspective, types: [] };
  }
  const types = getBreakdownEntityTypes(resolvedWidget.dataSelection[0]?.filters, perspective);
  // Sorted: the same types in another order are the same request, read once
  return { perspective, types: resolveBreakdownTypeVariables(types, variables).sort() };
};

// Label of a field: the one of the perspective, or of its filter in the schema, the key itself otherwise
const getBreakdownFieldLabel = (
  filterKeysSchema: Map<string, Map<string, FilterDefinition>>,
  perspective: WidgetPerspective,
  key: string,
) => {
  const breakdownPerspective = getBreakdownPerspective(perspective);
  const perspectiveLabel = perspective === 'audits'
    ? AUDITS_BREAKDOWN_LABELS.get(key)
    : breakdownPerspective && [breakdownPerspective.typeField, ...breakdownPerspective.fields].find((field) => field.key === key)?.label;
  if (perspectiveLabel) {
    return perspectiveLabel;
  }
  const definitions = [...filterKeysSchema.values()].find((typeDefinitions) => typeDefinitions.has(key));
  return definitions?.get(key)?.label ?? key;
};

/**
 * Fields offered for the `keys` of the fields the API lists for the dataset (fetchTimeSeriesBreakdownFields),
 * labelled after the perspective, or after their filter. They are ordered by their `translate`d label, but the
 * fields of the logs, which keep the order of the API.
 */
export const getBreakdownFieldOptions = (
  filterKeysSchema: Map<string, Map<string, FilterDefinition>>,
  keys: readonly string[],
  perspective: WidgetPerspective,
  translate: (label: string) => string = (label) => label,
): BreakdownField[] => {
  const options = keys.map((key) => ({ key, label: getBreakdownFieldLabel(filterKeysSchema, perspective, key) }));
  return perspective === 'audits' ? options : options.sort((a, b) => translate(a.label).localeCompare(translate(b.label)));
};

/**
 * Breakdown of the edited widget, on the dataset its query reads: the content of its saved filter once read
 * (`savedFilter`), and the keys of the fields the API lists for it once read (`fields`, asked as
 * getBreakdownFieldsRequest says). Its field is kept while they are read, or when one of them cannot be: the
 * fields of the dataset are unknown. Once they are known, only a field the API lists is kept: the type of a
 * single type, which makes a single series, is not. The labels are `translate`d to order the options.
 */
export const getWidgetBreakdownState = ({
  filterKeysSchema,
  widget,
  host,
  savedFilter,
  fields,
  translate,
}: {
  filterKeysSchema: Map<string, Map<string, FilterDefinition>>;
  widget: BreakdownWidget & ConfiguredWidget;
  host: WidgetHost;
  savedFilter: SavedFilterContent;
  fields: { resolution: BreakdownResolution; keys?: readonly string[] | null };
  translate?: (label: string) => string;
}): WidgetBreakdownState => {
  // Read on the content of the saved filter: it can select draft workspaces
  const editorState = getBreakdownEditorState(withSavedFilter(widget, savedFilter), host);
  if (editorState === 'hidden') {
    return { ...NO_BREAKDOWN_STATE, resolution: savedFilter.resolution, savedFilterResolution: savedFilter.resolution };
  }
  const perspective = widget.perspective ?? 'entities';
  const fieldKeys = fields.resolution === 'resolved' ? fields.keys ?? [] : [];
  const fieldOptions = getBreakdownFieldOptions(filterKeysSchema, fieldKeys, perspective, translate);
  const resolution = combineResolutions(savedFilter.resolution, fields.resolution);
  const breakdownBy = widget.parameters?.breakdownBy;
  const storedField = isBreakdownField(breakdownBy) ? breakdownBy : null;
  const isFieldKept = editorState === 'editable' && !!storedField && (resolution !== 'resolved' || fieldKeys.includes(storedField));
  const field = isFieldKept ? storedField : null;
  const unlistedField = field && !fieldOptions.some(({ key }) => key === field)
    ? { key: field, label: getBreakdownFieldLabel(filterKeysSchema, perspective, field) }
    : null;
  return { editorState, fieldOptions, resolution, savedFilterResolution: savedFilter.resolution, field, unlistedField };
};

/**
 * The widget as submitted: without breakdown when the editor does not keep its field (WidgetBreakdownState),
 * as the widget, or its dataset, can no longer be broken down by it, instead of keeping a setting that
 * would be silently ignored. Applied once, on submit: until then the field stays, so that a widget turned
 * into another visualization and back, or whose filters are changed and changed back, keeps its breakdown.
 */
export const applyBreakdownCompatibility = <T extends ConfiguredWidget>(widget: T, breakdown: Pick<WidgetBreakdownState, 'field'>): T => {
  if (!widget.parameters?.breakdownBy || breakdown.field) {
    return widget;
  }
  return clearBreakdown(widget);
};
