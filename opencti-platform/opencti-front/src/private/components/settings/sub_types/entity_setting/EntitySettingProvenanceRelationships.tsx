import React, { Suspense, useMemo, useState } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import Box from '@mui/material/Box';
import Stack from '@mui/material/Stack';
import { Button, SearchField, Select, SelectContent, SelectItem, SelectTrigger, SelectValue, Text, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import Card from '@common/card/Card';
import { useFormatter } from '../../../../../components/i18n';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import useQueryLoading from '../../../../../utils/hooks/useQueryLoading';
import { notifyPayloadErrors } from '../../../common/provenance/provenanceUtils';
import { EntitySettingProvenanceRelationships_entitySetting$key } from './__generated__/EntitySettingProvenanceRelationships_entitySetting.graphql';
import { EntitySettingProvenanceRelationshipsEditMutation } from './__generated__/EntitySettingProvenanceRelationshipsEditMutation.graphql';
import { ProvenanceTrackingRowStatisticsQuery } from './__generated__/ProvenanceTrackingRowStatisticsQuery.graphql';
import ProvenanceTrackingRow, {
  PROVENANCE_RELATIONSHIP_TYPES_DOCUMENTATION,
  provenanceTrackingRowStatisticsQuery,
  provenanceTrackingRowSx,
  type ProvenanceTypeStatistics,
} from './ProvenanceTrackingRow';

const entitySettingProvenanceRelationshipsFragment = graphql`
  fragment EntitySettingProvenanceRelationships_entitySetting on EntitySetting {
    id
    provenance_relationship_tracking {
      relationship_type
      tracked
      recommended
    }
  }
`;

const entitySettingProvenanceRelationshipsEditMutation = graphql`
  mutation EntitySettingProvenanceRelationshipsEditMutation($relationshipTypes: [String!]!, $tracked: Boolean!) {
    provenanceRelationshipTrackingEdit(relationship_types: $relationshipTypes, tracked: $tracked) {
      ...EntitySettingsFragment_entitySetting
      ...EntitySettingProvenanceRelationships_entitySetting
    }
  }
`;

type TrackingFilter = 'all' | 'tracked' | 'untracked';

interface RelationshipTypeTracking {
  type: string;
  label: string;
  tracked: boolean;
  recommended: boolean;
}

interface RelationshipRowsProps {
  rows: RelationshipTypeTracking[];
  // undefined while the statistics load
  statistics: Map<string, ProvenanceTypeStatistics> | undefined;
  onTrackedChange: (types: string[], tracked: boolean) => void;
}

const RelationshipRows = ({ rows, statistics, onTrackedChange }: RelationshipRowsProps) => {
  const { t_i18n } = useFormatter();
  return (
    <>
      {rows.map((row) => (
        <ProvenanceTrackingRow
          key={row.type}
          label={row.label}
          switchLabel={t_i18n('Track {type}', { values: { type: row.label } })}
          tracked={row.tracked}
          recommended={row.recommended}
          statistics={statistics ? (statistics.get(row.type) ?? null) : undefined}
          onTrackedChange={(tracked) => onTrackedChange([row.type], tracked)}
        />
      ))}
    </>
  );
};

const RelationshipRowsWithStatistics = ({ queryRef, ...props }: Omit<RelationshipRowsProps, 'statistics'> & { queryRef: PreloadedQuery<ProvenanceTrackingRowStatisticsQuery> }) => {
  const { provenanceTypeStatistics } = usePreloadedQuery(provenanceTrackingRowStatisticsQuery, queryRef);
  const statistics = useMemo(() => new Map(provenanceTypeStatistics.map((entry) => [entry.entity_type, entry])), [provenanceTypeStatistics]);
  return <RelationshipRows {...props} statistics={statistics} />;
};

interface EntitySettingProvenanceRelationshipsProps {
  entitySettingData: EntitySettingProvenanceRelationships_entitySetting$key;
}

/**
 * Provenance tracking of each relationship type: a dense list with the knowledge already asserted per type.
 */
const EntitySettingProvenanceRelationships = ({ entitySettingData }: EntitySettingProvenanceRelationshipsProps) => {
  const { t_i18n, n } = useFormatter();
  const entitySetting = useFragment(entitySettingProvenanceRelationshipsFragment, entitySettingData);
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState<TrackingFilter>('all');
  // Switches follow the click at once, the stored value takes over when the mutation settles
  const [pending, setPending] = useState<Record<string, boolean>>({});
  const [commit] = useApiMutation<EntitySettingProvenanceRelationshipsEditMutation>(entitySettingProvenanceRelationshipsEditMutation);
  const queryRef = useQueryLoading<ProvenanceTrackingRowStatisticsQuery>(provenanceTrackingRowStatisticsQuery, { types: ['stix-core-relationship'] });

  const relationshipTypes: RelationshipTypeTracking[] = useMemo(() => entitySetting.provenance_relationship_tracking
    .map((entry) => ({
      type: entry.relationship_type,
      label: t_i18n(`relationship_${entry.relationship_type}`),
      tracked: pending[entry.relationship_type] ?? entry.tracked,
      recommended: entry.recommended,
    }))
    // Recommended types first: the order never depends on a switch, so a row does not move when it is clicked
    .sort((a, b) => Number(b.recommended) - Number(a.recommended) || a.label.localeCompare(b.label)), [entitySetting.provenance_relationship_tracking, pending, t_i18n]);

  const setTracking = (types: string[], tracked: boolean) => {
    setPending((current) => ({ ...current, ...Object.fromEntries(types.map((type) => [type, tracked])) }));
    const settle = () => setPending((current) => Object.fromEntries(Object.entries(current).filter(([type]) => !types.includes(type))));
    commit({
      variables: { relationshipTypes: types, tracked },
      onCompleted: (_, errors) => {
        notifyPayloadErrors(errors);
        settle();
      },
      onError: settle,
    });
  };

  const trackedCount = relationshipTypes.filter((entry) => entry.tracked).length;
  const recommended = relationshipTypes.filter((entry) => entry.recommended);
  const isRecommendedTracked = recommended.every((entry) => entry.tracked);
  const keyword = search.trim().toLowerCase();
  const visible = relationshipTypes.filter((entry) => {
    const isFilterMatch = filter === 'all' || (filter === 'tracked') === entry.tracked;
    return isFilterMatch && (keyword.length === 0 || entry.label.toLowerCase().includes(keyword) || entry.type.includes(keyword));
  });
  const recommendedLabels = recommended.map((entry) => entry.label).join(', ');
  const clearSearch = () => {
    setSearch('');
    setFilter('all');
  };
  const rowsProps = { rows: visible, onTrackedChange: setTracking };

  const recommendedAction = (
    <Tooltip>
      <TooltipTrigger asChild>
        {/* A disabled button receives no pointer event: the wrapper keeps the tooltip reachable */}
        <span
          tabIndex={isRecommendedTracked ? 0 : -1}
          className="inline-flex rounded-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-filigran-brand-primary focus-visible:ring-offset-2 focus-visible:ring-offset-focus"
        >
          <Button
            priority="secondary"
            size="sm"
            disabled={isRecommendedTracked}
            onClick={() => setTracking(recommended.map((entry) => entry.type), true)}
          >
            {t_i18n('Apply recommended')}
          </Button>
        </span>
      </TooltipTrigger>
      <TooltipContent>
        {isRecommendedTracked
          ? t_i18n('The recommended types ({types}) are tracked.', { values: { types: recommendedLabels } })
          : t_i18n('Also tracks {types}, the other types are unchanged.', { values: { types: recommendedLabels } })}
      </TooltipContent>
    </Tooltip>
  );

  return (
    <Card title={t_i18n('Provenance')} action={recommendedAction}>
      <Stack gap={1.5} data-testid="entity-setting-provenance-relationships">
        <Text variant="content-caption" as="p">
          {t_i18n('Records who asserts the relationships of the types switched on, to measure their corroboration and freshness.')}
          {' '}
          <Text variant="content-compact-link" as="a" href={PROVENANCE_RELATIONSHIP_TYPES_DOCUMENTATION} target="_blank" rel="noreferrer">
            {t_i18n('Learn more')}
          </Text>
        </Text>
        <Stack direction="row" gap={1} alignItems="center" flexWrap="wrap">
          <Box sx={{ flex: '1 1 220px', maxWidth: 320 }}>
            <SearchField
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              onClear={() => setSearch('')}
              placeholder={t_i18n('Search a relationship type')}
              aria-label={t_i18n('Search a relationship type')}
              clearLabel={t_i18n('Clear the search')}
            />
          </Box>
          <Box sx={{ width: 160 }}>
            <Select value={filter} onValueChange={(value: string) => setFilter(value as TrackingFilter)}>
              <SelectTrigger aria-label={t_i18n('Filter by tracking')}>
                <SelectValue />
              </SelectTrigger>
              <SelectContent aria-label={t_i18n('Filter by tracking')}>
                <SelectItem value="all">{t_i18n('All types')}</SelectItem>
                <SelectItem value="tracked">{t_i18n('Tracked')}</SelectItem>
                <SelectItem value="untracked">{t_i18n('Not tracked')}</SelectItem>
              </SelectContent>
            </Select>
          </Box>
          <Text variant="content-caption" as="span" aria-live="polite" style={{ marginLeft: 'auto' }}>
            {t_i18n('{tracked} of {total} relationship types tracked', { values: { tracked: n(trackedCount), total: n(relationshipTypes.length) } })}
          </Text>
        </Stack>
        <Box
          role="table"
          aria-label={t_i18n('Provenance tracking per relationship type')}
          sx={{ maxHeight: 360, overflowY: 'auto', border: '1px solid var(--border-elevation-subtle)', borderRadius: 1 }}
        >
          <Box
            role="row"
            sx={{
              ...provenanceTrackingRowSx,
              minHeight: 32,
              position: 'sticky',
              top: 0,
              zIndex: 1,
              background: 'var(--bg-elevation-default-layer-2)',
              borderBottom: '1px solid var(--border-elevation-subtle)',
            }}
          >
            <Text variant="content-caption" as="span" role="columnheader">{t_i18n('Relationship type')}</Text>
            <Text variant="content-caption" as="span" role="columnheader">{t_i18n('Assertions')}</Text>
            <Text variant="content-caption" as="span" role="columnheader">{t_i18n('Last assertion')}</Text>
            <Text variant="content-caption" as="span" role="columnheader">{t_i18n('Tracked')}</Text>
          </Box>
          {visible.length === 0 ? (
            <Stack role="row" direction="row" gap={1} alignItems="center" justifyContent="center" sx={{ py: 2 }}>
              <Text variant="content-compact" as="span" role="cell">{t_i18n('No relationship type matches this search.')}</Text>
              <Button priority="tertiary" size="sm" onClick={clearSearch}>{t_i18n('Clear the search')}</Button>
            </Stack>
          ) : (
            <Suspense fallback={<RelationshipRows {...rowsProps} statistics={undefined} />}>
              {queryRef
                ? <RelationshipRowsWithStatistics {...rowsProps} queryRef={queryRef} />
                : <RelationshipRows {...rowsProps} statistics={undefined} />}
            </Suspense>
          )}
        </Box>
      </Stack>
    </Card>
  );
};

export default EntitySettingProvenanceRelationships;
