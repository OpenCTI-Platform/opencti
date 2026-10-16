import React, { useEffect, useState } from 'react';
import { graphql } from 'react-relay';
import { v4 as uuid } from 'uuid';
import { useTheme } from '@mui/styles';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue, Text } from '@filigran/design-system';
import Button from '@common/button/Button';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
import { fetchQuery } from '../../../relay/environment';
import type { Filter, FilterGroup, handleFilterHelpers } from '../../../utils/filters/filtersHelpers-types';
import { extractAllFilters } from '../../../utils/filters/filtersUtils';
import useHuntConfiguration from './useHuntConfiguration';
import { HuntIocFilterTakeQuery, HuntIocSort } from './__generated__/HuntIocFilterTakeQuery.graphql';

export const HUNT_IOC_SORT_DEFAULT: HuntIocSort = 'created_at_desc';
const HUNT_IOC_SORTS: HuntIocSort[] = ['created_at_desc', 'created_at_asc', 'updated_at_desc', 'updated_at_asc'];
// The count waits for the user to stop editing the filter before asking the platform
const COUNT_DELAY_MS = 400;

const huntIocFilterTakeQuery = graphql`
  query HuntIocFilterTakeQuery($id: String!, $filters: String, $sort: HuntIocSort) {
    hunt(id: $id) {
      id
      iocFilterPreview(filters: $filters, sort: $sort) {
        matching_count
        taken_count
      }
    }
  }
`;

export const huntIocSortLabel = (sort: HuntIocSort, t_i18n: (key: string) => string) => {
  switch (sort) {
    case 'created_at_asc':
      return t_i18n('Oldest created first');
    case 'updated_at_desc':
      return t_i18n('Recently updated first');
    case 'updated_at_asc':
      return t_i18n('Least recently updated first');
    default:
      return t_i18n('Newest created first');
  }
};

export const HUNTED_AT_FILTER_KEY = 'x_opencti_hunted_at';

const groupOfFilter = (group: FilterGroup, filterId: string): FilterGroup | undefined => {
  if ((group.filters ?? []).some((filter) => filter.id === filterId)) {
    return group;
  }
  return (group.filterGroups ?? []).map((subGroup) => groupOfFilter(subGroup, filterId)).find((found) => !!found);
};

/**
 * Leaves the entities already hunted out of the filter of a hunt: a group of its own keeps the entities never hunted or
 * hunted before a date. The group is created with its first condition, the second one joins it once the group exists.
 */
export const useHuntedExclusion = ([filters, helpers]: [FilterGroup, handleFilterHelpers]) => {
  const [pendingFilterId, setPendingFilterId] = useState<string | null>(null);
  useEffect(() => {
    const group = pendingFilterId ? groupOfFilter(filters, pendingFilterId) : undefined;
    if (!group?.id) {
      return;
    }
    setPendingFilterId(null);
    const neverHunted: Filter = { id: uuid(), key: HUNTED_AT_FILTER_KEY, operator: 'nil', values: [], mode: 'or' };
    helpers.handleAddFilterWithEmptyValue(neverHunted, group.id);
    helpers.handleSwitchGlobalMode(group.id);
  }, [filters, pendingFilterId]);
  const excluded = extractAllFilters(filters).some((filter) => filter.key === HUNTED_AT_FILTER_KEY);
  const exclude = (date: string) => {
    const huntedBefore: Filter = { id: uuid(), key: HUNTED_AT_FILTER_KEY, operator: 'lt', values: [date], mode: 'or' };
    setPendingFilterId(huntedBefore.id ?? null);
    helpers.handleAddFilterGroup(undefined, huntedBefore);
  };
  return { excluded, exclude };
};

interface HuntIocFilterTakeProps {
  huntId: string;
  /** The filter as edited, serialized for the platform; null when it holds no filter */
  filters: string | null;
  sort: HuntIocSort;
  onSortChange: (sort: HuntIocSort) => void;
  disabled?: boolean;
  /** The date of the latest run of the hunt, which the exclusion of the entities already hunted starts from */
  lastRunAt?: string | null;
  /** Whether the filter leaves out the entities already hunted */
  huntedExcluded?: boolean;
  onExcludeHunted?: (date: string) => void;
}

/**
 * What a run takes out of the filter of an indicator hunt: at most the limit of the platform, in the order chosen
 * here, with the count of what the filter as edited matches.
 */
const HuntIocFilterTake = ({ huntId, filters, sort, onSortChange, disabled = false, lastRunAt, huntedExcluded = false, onExcludeHunted }: HuntIocFilterTakeProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n, fldt } = useFormatter();
  const { maxFilterEntitiesPerRun } = useHuntConfiguration();
  const [count, setCount] = useState<{ matching_count: number; taken_count: number } | null>(null);
  useEffect(() => {
    setCount(null);
    if (!filters) return undefined;
    let current = true;
    const timer = setTimeout(() => {
      fetchQuery<HuntIocFilterTakeQuery>(huntIocFilterTakeQuery, { id: huntId, filters, sort }).toPromise()
        .then((data) => {
          if (current) setCount(data?.hunt?.iocFilterPreview ?? null);
        })
        .catch(() => undefined);
    }, COUNT_DELAY_MS);
    return () => {
      current = false;
      clearTimeout(timer);
    };
  }, [huntId, filters, sort]);
  const caption = { display: 'block', color: theme.palette.text.secondary };
  let countLine: string | null = null;
  if (filters && count) {
    if (count.matching_count === 0) {
      countLine = t_i18n('No indicator or observable the hunt can take matches the filter');
    } else if (count.taken_count < count.matching_count) {
      countLine = t_i18n('{count, number} indicators and observables match the filter: the next run takes {taken, number} of them, in the order above', {
        values: { count: count.matching_count, taken: count.taken_count },
      });
    } else {
      countLine = t_i18n('{count, number} indicators and observables match the filter: the next run takes them all', { values: { count: count.matching_count } });
    }
  }
  return (
    <div style={{ marginTop: theme.spacing(1), display: 'flex', flexDirection: 'column', gap: theme.spacing(0.5) }} data-testid="hunt-ioc-filter-take">
      <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), flexWrap: 'wrap' }}>
        <Text variant="content-caption" style={{ color: theme.palette.text.secondary }}>
          {t_i18n('Each run takes at most {max} of them:', { values: { max: maxFilterEntitiesPerRun } })}
        </Text>
        <Select value={sort} onValueChange={(value) => onSortChange(value as HuntIocSort)} disabled={disabled}>
          <SelectTrigger aria-label={t_i18n('Order of the indicators and observables taken from the filter')} style={{ minWidth: 220 }} data-testid="hunt-ioc-sort">
            <SelectValue />
          </SelectTrigger>
          <SelectContent aria-label={t_i18n('Order of the indicators and observables taken from the filter')}>
            {HUNT_IOC_SORTS.map((value) => <SelectItem key={value} value={value}>{huntIocSortLabel(value, t_i18n)}</SelectItem>)}
          </SelectContent>
        </Select>
      </div>
      {countLine && (
        <Text variant="content-caption" style={caption} role="status" aria-live="polite" data-testid="hunt-ioc-filter-count">{countLine}</Text>
      )}
      {/* Worth it only when the filter holds more than a run takes: the next runs go through the entities not hunted yet */}
      {count && count.taken_count < count.matching_count && lastRunAt && !huntedExcluded && onExcludeHunted && !disabled && (
        <div>
          <Button variant="tertiary" size="small" onClick={() => onExcludeHunted(lastRunAt)} data-testid="hunt-ioc-exclude-hunted">
            {t_i18n('Exclude the entities hunted since {date}', { values: { date: fldt(lastRunAt) } })}
          </Button>
        </div>
      )}
    </div>
  );
};

export default HuntIocFilterTake;
