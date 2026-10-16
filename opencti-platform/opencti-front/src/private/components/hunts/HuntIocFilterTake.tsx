import React, { useEffect, useState } from 'react';
import { graphql } from 'react-relay';
import { useTheme } from '@mui/styles';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue, Text } from '@filigran/design-system';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
import { fetchQuery } from '../../../relay/environment';
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

interface HuntIocFilterTakeProps {
  huntId: string;
  /** The filter as edited, serialized for the platform; null when it holds no filter */
  filters: string | null;
  sort: HuntIocSort;
  onSortChange: (sort: HuntIocSort) => void;
  disabled?: boolean;
}

/**
 * What a run takes out of the filter of an indicator hunt: at most the limit of the platform, in the order chosen
 * here, with the count of what the filter as edited matches.
 */
const HuntIocFilterTake = ({ huntId, filters, sort, onSortChange, disabled = false }: HuntIocFilterTakeProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
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
    </div>
  );
};

export default HuntIocFilterTake;
