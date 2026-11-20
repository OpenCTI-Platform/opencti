import React from 'react';
import { AccountBalanceOutlined, CenterFocusStrongOutlined, DateRangeOutlined, FilterAltOffOutlined, FilterListOutlined } from '@mui/icons-material';
import type { ToolbarAction } from '../../../../../components/graph/ToolbarShell';
import { countTimeRangeFilters, type GraphTimeRange } from '../../../../../components/graph/utils/graphTimeRange';
import { useFormatter } from '../../../../../components/i18n';
import { jsDate } from '../../../../../utils/Time';
import { hasActiveMatrixFilters, type InvestigationMatrixFilters, type MatrixFilterOptions, type MatrixRelationshipType } from './matrixFilters';
import type { MatrixToolbarGroup } from './InvestigationMatrixToolbar';

const ICON = { fontSize: 'medium' } as const;

const toggle = <T extends string>(list: T[], item: T): T[] => {
  return list.includes(item) ? list.filter((value) => value !== item) : [...list, item];
};

/** The stored range as the time range panel reads it; undefined for the whole range. */
export const matrixTimeRangeInterval = (filters: InvestigationMatrixFilters): [Date, Date] | undefined => {
  return filters.timeRange ? [jsDate(filters.timeRange[0]), jsDate(filters.timeRange[1])] : undefined;
};

/**
 * The filters of the matrix toolbar, as the graph's: same ids, priorities and icons, but they act on
 * the matrix filters of the investigation and never on the graph state.
 */
export const useInvestigationMatrixFilterActions = ({
  options,
  timeRange,
  filters,
  onChange,
  onClear,
  timeRangeOpen,
  onToggleTimeRange,
}: {
  options: MatrixFilterOptions;
  /** The full range the time range panel draws, computed once by the matrix for the panel and the badge. */
  timeRange: GraphTimeRange;
  filters: InvestigationMatrixFilters;
  onChange: (change: Partial<InvestigationMatrixFilters>) => void;
  onClear: () => void;
  timeRangeOpen: boolean;
  onToggleTimeRange: () => void;
}): ToolbarAction<MatrixToolbarGroup>[] => {
  const { t_i18n } = useFormatter();
  const { entityTypes, relationshipTypes, markings, authors } = options;
  const { disabledEntityTypes, disabledRelationshipTypes, disabledMarkings, disabledCreators } = filters;

  const typeOptions = [
    ...entityTypes.map((type) => ({
      key: `entity:${type}`,
      label: t_i18n(`entity_${type}`),
      section: t_i18n('Entities'),
      selected: !disabledEntityTypes.includes(type),
    })),
    ...relationshipTypes.map((type) => ({
      key: `relationship:${type}`,
      label: t_i18n(`relationship_${type}`),
      section: t_i18n('Relationships'),
      selected: !disabledRelationshipTypes.includes(type),
    })),
  ];
  // The badges count what is filtered out among what the investigation holds: a stored id of a marking
  // or a type no longer in it filters nothing. "Clear all filters" still follows every stored filter.
  const unselectedCount = (items: { selected: boolean }[]) => items.filter(({ selected }) => !selected).length;
  const markingOptions = markings.map(({ id, definition }) => ({ key: id, label: definition, selected: !disabledMarkings.includes(id) }));
  const authorOptions = authors.map(({ id, name }) => ({ key: id, label: name, selected: !disabledCreators.includes(id) }));

  return [
    {
      id: 'filter-types',
      group: 'filters',
      priority: 85,
      label: t_i18n('Filter by type'),
      description: t_i18n('Choose which linked entity types and relationship types (uses, indicates, contains) count towards the heatmap.'),
      icon: <FilterListOutlined {...ICON} />,
      badge: unselectedCount(typeOptions),
      disabledReason: typeOptions.length === 0 ? t_i18n('No attack pattern is linked to an entity in this investigation') : undefined,
      options: {
        multiple: true,
        items: typeOptions,
        onSelect: (key) => {
          const separator = key.indexOf(':');
          const [kind, type] = [key.slice(0, separator), key.slice(separator + 1)];
          if (kind === 'relationship') onChange({ disabledRelationshipTypes: toggle(disabledRelationshipTypes, type as MatrixRelationshipType) });
          else onChange({ disabledEntityTypes: toggle(disabledEntityTypes, type) });
        },
      },
    },
    {
      id: 'time-range',
      group: 'filters',
      priority: 70,
      label: t_i18n('Time range'),
      description: t_i18n('Count only the relationships dated within the range you set.'),
      icon: <DateRangeOutlined {...ICON} />,
      pressed: timeRangeOpen,
      badge: countTimeRangeFilters(timeRange.interval, matrixTimeRangeInterval(filters)),
      onSelect: onToggleTimeRange,
    },
    {
      id: 'filter-markings',
      group: 'filters',
      priority: 45,
      label: t_i18n('Filter by marking'),
      description: t_i18n('Count only the data with the markings you keep.'),
      icon: <CenterFocusStrongOutlined {...ICON} />,
      badge: unselectedCount(markingOptions),
      disabledReason: markings.length === 0 ? t_i18n('No marking in this graph') : undefined,
      options: {
        multiple: true,
        items: markingOptions,
        onSelect: (id) => onChange({ disabledMarkings: toggle(disabledMarkings, id) }),
      },
    },
    {
      id: 'filter-authors',
      group: 'filters',
      priority: 45,
      label: t_i18n('Filter by author'),
      description: t_i18n('Count only the data from the authors you keep.'),
      icon: <AccountBalanceOutlined {...ICON} />,
      badge: unselectedCount(authorOptions),
      disabledReason: authors.length === 0 ? t_i18n('No author in this graph') : undefined,
      options: {
        multiple: true,
        items: authorOptions,
        onSelect: (id) => onChange({ disabledCreators: toggle(disabledCreators, id) }),
      },
    },
    {
      id: 'clear-filters',
      group: 'filters',
      priority: 60,
      label: t_i18n('Clear all filters'),
      description: t_i18n('Remove every filter set on the Matrix view and show the whole matrix again.'),
      icon: <FilterAltOffOutlined {...ICON} />,
      disabledReason: hasActiveMatrixFilters(filters) ? undefined : t_i18n('No filter is active'),
      onSelect: onClear,
    },
  ];
};
