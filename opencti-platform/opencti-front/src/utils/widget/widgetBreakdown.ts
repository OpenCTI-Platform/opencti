import type { Widget, WidgetHost, WidgetParameters, WidgetPerspective } from './widget';
import { getCurrentCategory } from './widgetUtils';
import { isDraftWorkspaceFilterGroup } from '../filters/filtersUtils';
import type { FilterGroup } from '../filters/filtersHelpers-types';
import type { FilterDefinition } from '../hooks/useAuth';
import { isCustomFieldAttribute } from '../customFields';
import type { DashboardVariable } from '../../components/dashboard/dashboard-types';
import { parseVariableToken } from '../../components/dashboard/dashboardVariablesResolution';

export const BREAKDOWN_LIMIT_OPTIONS = [5, 10, 20, 50];
export const DEFAULT_BREAKDOWN_LIMIT = 10;

// Draft workspaces cannot be broken down: read on the filters of the widget, or on the content of its saved filter
const isDraftWorkspaceDataset = (dataSelection: Widget['dataSelection']) => isDraftWorkspaceFilterGroup(dataSelection[0]?.filters);

// Relation refs and id attributes with a small, stable cardinality. Vocabularies and enums are
// always allowed, whatever their key. The backend enforces the same fields, split in three
// (opencti-graphql/src/database/middleware.ts): BREAKDOWN_ALLOWED_REFS for the relation refs,
// BREAKDOWN_ALLOWED_ID_ATTRIBUTES for creator_id, and the fields of each perspective below
// (resolveBreakdownField and resolveRelationshipBreakdownField). Keep them in sync.
export const BREAKDOWN_ALLOWED_REFS = ['createdBy', 'objectLabel', 'objectMarking', 'objectAssignee', 'objectParticipant', 'creator_id'];
const BREAKDOWN_VALUE_FILTER_TYPES = ['vocabulary', 'enum'];
const isBreakdownAllowedKey = (key: string, type: string) => {
  return BREAKDOWN_ALLOWED_REFS.includes(key) || BREAKDOWN_VALUE_FILTER_TYPES.includes(type);
};
// Filter keys computed at query time, not stored on the entities: the API refuses them
const COMPUTED_FILTER_KEYS = ['computed_reliability', 'workflow_id', 'workflowInstanceCurrentState', 'connectedToId', 'ids', 'id'];
// Only set inside drafts, where breakdowns are not available: every value would be empty
const DRAFT_FILTER_KEYS = ['draft_change.draft_operation'];
// Fields of the history and activity logs, as indexed, in the order they are offered. The backend accepts
// exactly these (HISTORY_BREAKDOWN_FIELDS in opencti-graphql/src/database/middleware.ts): keep them in sync.
// The context entity id and the free texts (messages, searches) are refused for their unbounded cardinality.
export const AUDITS_BREAKDOWN_FIELDS: { key: string; label: string }[] = [
  { key: 'event_type', label: 'Event type' },
  { key: 'event_scope', label: 'Event_scope' },
  { key: 'user_id', label: 'User' },
  { key: 'group_ids', label: 'Group' },
  { key: 'organization_ids', label: 'Organization' },
  { key: 'entity_type', label: 'Entity_type' },
  { key: 'context_data.entity_type', label: 'Type of related entity' },
];

type BreakdownField = { key: string; label: string };
interface BreakdownPerspective {
  // Filter key restricting the types of the dataset
  typeFilterKey: string;
  // Types of the dataset without such a filter
  defaultTypes: string[];
  // The type itself, offered when the dataset is not restricted to a single type
  typeField: BreakdownField;
  // Fields of the perspective that are not read from the schema
  fields: BreakdownField[];
}
const BREAKDOWN_PERSPECTIVES: Partial<Record<WidgetPerspective, BreakdownPerspective>> = {
  entities: {
    typeFilterKey: 'entity_type',
    defaultTypes: ['Stix-Core-Object'],
    typeField: { key: 'entity_type', label: 'Entity type' },
    fields: [],
  },
  relationships: {
    typeFilterKey: 'relationship_type',
    // Every relationship, as the relationships time series without relationship type
    defaultTypes: ['stix-relationship'],
    typeField: { key: 'relationship_type', label: 'Relationship type' },
    // Each relationship has a single source and a single target, among a bounded number of types
    fields: [{ key: 'fromTypes', label: 'Source type' }, { key: 'toTypes', label: 'Target type' }],
  },
};
const getBreakdownPerspective = (perspective?: WidgetPerspective | null) => {
  return perspective ? BREAKDOWN_PERSPECTIVES[perspective] : undefined;
};
// Perspectives with a breakdown API: the schema-based ones above, and the audits with their own fields
const isBreakdownPerspective = (perspective?: WidgetPerspective | null) => {
  return perspective === 'audits' || !!getBreakdownPerspective(perspective);
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

/**
 * Fields the dataset can be broken down by: with a single type, its allowed fields
 * (BREAKDOWN_ALLOWED_REFS, vocabularies and enums); with several types, the ones they have in common,
 * plus the type itself, also offered for a single abstract type, which holds several concrete ones.
 * Relationships can also be broken down by the type of their source or target.
 * The fields are ordered by their label as shown, `translate`d.
 */
export const getBreakdownFieldOptions = (
  filterKeysSchema: Map<string, Map<string, FilterDefinition>>,
  entityTypes: string[],
  perspective: WidgetPerspective = 'entities',
  translate: (label: string) => string = (label) => label,
): BreakdownField[] => {
  const breakdownPerspective = getBreakdownPerspective(perspective);
  if (!breakdownPerspective) return [];
  const types = entityTypes.length > 0 ? entityTypes : breakdownPerspective.defaultTypes;
  const schemas = types.map((type) => filterKeysSchema.get(type) ?? new Map<string, FilterDefinition>());
  const options: BreakdownField[] = [];
  schemas[0].forEach((definition, key) => {
    // Abstract types also list the keys of some of their sub types: keep the keys of the type itself
    const isCommon = types.every((type, index) => schemas[index].get(key)?.subEntityTypes.includes(type));
    // Custom fields are not stored as attributes: the API cannot break them down
    const isStored = !COMPUTED_FILTER_KEYS.includes(key) && !DRAFT_FILTER_KEYS.includes(key) && !isCustomFieldAttribute(key);
    if (isCommon && isBreakdownAllowedKey(key, definition.type) && isStored) {
      options.push({ key, label: definition.label });
    }
  });
  options.push(...breakdownPerspective.fields);
  // A single type is abstract when its keys are also carried by its sub types
  const isAbstractType = [...schemas[0].values()].some(({ subEntityTypes }) => subEntityTypes.some((subType) => subType !== types[0]));
  if (entityTypes.length !== 1 || isAbstractType) {
    options.push(breakdownPerspective.typeField);
  }
  return options.sort((a, b) => translate(a.label).localeCompare(translate(b.label)));
};

/**
 * Fields the first dataset of the widget can be broken down by: the fields of its entity or relationship
 * types for the entities and the relationships, the allowed fields of the logs for the audits.
 * The dataset filters are the ones of the widget, its saved filters read: its type variables are
 * resolved with the dashboard `variables`. None for draft workspaces, which a saved filter can select.
 * The audits fields keep their order, the others are ordered by their `translate`d label.
 */
export const getWidgetBreakdownFieldOptions = (
  filterKeysSchema: Map<string, Map<string, FilterDefinition>>,
  widget: Pick<Widget, 'perspective' | 'dataSelection'>,
  variables?: DashboardVariable[],
  translate?: (label: string) => string,
): BreakdownField[] => {
  if (isDraftWorkspaceDataset(widget.dataSelection)) {
    return [];
  }
  if (widget.perspective === 'audits') {
    return AUDITS_BREAKDOWN_FIELDS;
  }
  const perspective = widget.perspective ?? 'entities';
  const types = resolveBreakdownTypeVariables(getBreakdownEntityTypes(widget.dataSelection[0]?.filters, perspective), variables);
  return getBreakdownFieldOptions(filterKeysSchema, types, perspective, translate);
};

/**
 * Whether the widget breakdown field can be used on its dataset, once its saved filters and variables
 * are resolved: saved or imported widgets can carry a field the API refuses for the entity types of
 * their filters, or for their perspective.
 */
export const isBreakdownFieldSupported = (
  filterKeysSchema: Map<string, Map<string, FilterDefinition>>,
  widget: Pick<Widget, 'perspective' | 'dataSelection' | 'parameters'>,
) => {
  const breakdownBy = widget.parameters?.breakdownBy;
  if (!breakdownBy || isDraftWorkspaceDataset(widget.dataSelection)) {
    return false;
  }
  // The API accepts the type itself for any dataset: it is only not offered for a single type, a single series.
  // A type variable may well hold a single type once resolved.
  if (getBreakdownPerspective(widget.perspective ?? 'entities')?.typeField.key === breakdownBy) {
    return true;
  }
  return getWidgetBreakdownFieldOptions(filterKeysSchema, widget).some(({ key }) => key === breakdownBy);
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

type BreakdownWidget = Pick<Widget, 'type' | 'perspective' | 'dataSelection'>;

// Audits lines and areas can count the distinct values of an attribute instead of the events
const AUDITS_DISTINCT_COUNT_TYPES = ['line', 'area'];
const isCountingDistinctValues = (widget: BreakdownWidget) => {
  return widget.perspective === 'audits'
    && AUDITS_DISTINCT_COUNT_TYPES.includes(widget.type)
    && widget.dataSelection.some((selection) => selection.unique === true);
};

// A breakdown expands the single dataset of a time series widget, counting its entities, relationships or events.
// A relationships widget can also hold entities datasets: they cannot be broken down as relationships.
const canWidgetBeBrokenDown = (widget: BreakdownWidget) => {
  const [dataset] = widget.dataSelection;
  return isBreakdownPerspective(widget.perspective)
    && getCurrentCategory(widget.type) === 'timeseries'
    && widget.dataSelection.length === 1
    && (dataset.perspective ?? widget.perspective) === widget.perspective
    && !isDraftWorkspaceDataset(widget.dataSelection)
    && !isCountingDistinctValues(widget);
};

// Hosts whose widgets can be broken down: the dashboards, and the custom views, whose widgets read the
// platform data the same way, around their entity. A fintel template writes its widgets in a document.
const BREAKDOWN_HOST_KINDS: WidgetHost['kind'][] = ['workspace', 'custom-view'];
const isBreakdownHost = (host?: WidgetHost) => !!host && BREAKDOWN_HOST_KINDS.includes(host.kind);

/**
 * Whether the breakdown can be configured: in workspace dashboards and custom views.
 */
export const isWidgetBreakdownEligible = (widget: BreakdownWidget, host?: WidgetHost) => {
  return isBreakdownHost(host) && canWidgetBeBrokenDown(widget);
};

/**
 * Whether the breakdown controls are shown: the widget could be broken down once reduced to its
 * first dataset, counting every event. getWidgetBreakdownLockReason says why they are disabled.
 */
export const isWidgetBreakdownConfigurable = (widget: BreakdownWidget, host?: WidgetHost) => {
  const [firstSelection] = widget.dataSelection;
  return !!firstSelection && isWidgetBreakdownEligible({ ...widget, dataSelection: [{ ...firstSelection, unique: false }] }, host);
};

/**
 * Why the breakdown of a configurable widget cannot be changed: a breakdown uses a single dataset,
 * and counts every event of the logs.
 */
export const getWidgetBreakdownLockReason = (widget: BreakdownWidget): 'several-datasets' | 'distinct-values' | undefined => {
  if (widget.dataSelection.length > 1) {
    return 'several-datasets';
  }
  if (isCountingDistinctValues(widget)) {
    return 'distinct-values';
  }
  return undefined;
};
