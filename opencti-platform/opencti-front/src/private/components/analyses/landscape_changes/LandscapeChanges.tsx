import React, { Suspense, useEffect, useRef, useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { useSearchParams } from 'react-router';
import { ProgressBar, Radio, RadioGroup, Select, SelectContent, SelectItem, SelectTrigger, SelectValue, Text } from '@filigran/design-system';
import { Alert, Box } from '@mui/material';
import Button from '@common/button/Button';
import Card from '@common/card/Card';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import { fetchQuery, MESSAGING$ } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useFiltersState from '../../../../utils/filters/useFiltersState';
import { serializeFilterGroupForBackend, useAvailableFilterKeysForEntityTypes } from '../../../../utils/filters/filtersUtils';
import FilterIconButton from '../../../../components/FilterIconButton';
import Filters from '../../common/lists/Filters';
import TimeMachinePeriodSelector from '../../common/time_machine/TimeMachinePeriodSelector';
import TimeMachineExportMenu from '../../common/time_machine/TimeMachineExportMenu';
import LandscapeChangesResults from '../../common/time_machine/LandscapeChangesResults';
import {
  DateRange,
  exportFileName,
  landscapeDiffToCsv,
  landscapeDiffToHtml,
  landscapeDiffToJson,
  LandscapeDiffData,
  presetRange,
} from '../../common/time_machine/timeMachineUtils';
import { LandscapeChangesRunMutation } from './__generated__/LandscapeChangesRunMutation.graphql';
import { LandscapeChangesPollQuery, LandscapeChangesPollQuery$data } from './__generated__/LandscapeChangesPollQuery.graphql';
import { LandscapeChangesScopesQuery } from './__generated__/LandscapeChangesScopesQuery.graphql';

const landscapeChangesRunMutation = graphql`
  mutation LandscapeChangesRunMutation($input: LandscapeDiffInput!) {
    landscapeDiffRun(input: $input) {
      id
      status
      progress
      total
    }
  }
`;

const landscapeChangesPollQuery = graphql`
  query LandscapeChangesPollQuery($id: ID!) {
    landscapeDiff(id: $id) {
      id
      status
      progress
      total
      from
      to
      group_by
      scope_entity_types
      error
      truncated
      aggregates {
        entities_in_scope
        entities_changed
        new_entities
        new_entities_by_type { key label count }
        new_relationships
        new_relationships_by_type { key label count }
        removed_relationships
        revocations
        confidence_changes
        score_changes
        new_techniques_by_tactic { key label count }
        new_techniques { id entity_type name count }
        new_malware { id entity_type name count }
        new_tools { id entity_type name count }
        new_victims_by_sector { key label count }
        new_victims_by_country { key label count }
        new_victims_by_region { key label count }
        new_infrastructure { id entity_type name count }
        new_infrastructure_count
        new_indicators_count
        groups { key label count }
      }
      entities {
        entity_id
        entity_type
        name
        created_in_period
        revoked_in_period
        attributes_changed
        relationships_added
        relationships_removed
        relationships_revoked
        confidence_before
        confidence_after
        score_before
        score_after
        change_score
      }
    }
  }
`;

const landscapeChangesScopesQuery = graphql`
  query LandscapeChangesScopesQuery {
    savedFilters(first: 500, orderBy: name, orderMode: asc) {
      edges {
        node {
          id
          name
          scope
        }
      }
    }
    customViews(first: 500, orderBy: name, orderMode: asc) {
      edges {
        node {
          id
          name
          targetEntityType
        }
      }
    }
  }
`;

type LandscapeDiffResult = NonNullable<LandscapeChangesPollQuery$data['landscapeDiff']>;
type ScopeMode = 'saved_filter' | 'custom_view' | 'filters';

const AUTO_ENTITY_TYPE = 'auto';
const LANDSCAPE_ENTITY_TYPES = [
  'Stix-Domain-Object',
  'Intrusion-Set',
  'Threat-Actor-Group',
  'Threat-Actor-Individual',
  'Campaign',
  'Malware',
  'Tool',
  'Attack-Pattern',
  'Vulnerability',
  'Incident',
  'Channel',
  'Report',
  'Sector',
  'Organization',
  'Country',
];
type LandscapeGroupBy = 'entity_type' | 'relationship_type' | 'tactic';
const POLL_INTERVAL_MS = 2000;
export const DIFF_SEARCH_PARAM = 'diff';

interface ScopeSelectorProps {
  mode: ScopeMode;
  savedFilterId: string;
  customViewId: string;
  onSavedFilterChange: (id: string) => void;
  onCustomViewChange: (id: string) => void;
}

const ScopeSelector = ({ mode, savedFilterId, customViewId, onSavedFilterChange, onCustomViewChange }: ScopeSelectorProps) => {
  const { t_i18n } = useFormatter();
  const data = useLazyLoadQuery<LandscapeChangesScopesQuery>(landscapeChangesScopesQuery, {}, { fetchPolicy: 'store-and-network' });
  const savedFilters = (data.savedFilters?.edges ?? []).map((edge) => edge?.node).filter((node) => !!node);
  const customViews = (data.customViews?.edges ?? []).map((edge) => edge?.node).filter((node) => !!node);
  if (mode === 'saved_filter') {
    if (savedFilters.length === 0) {
      return <Text variant="content-compact" style={{ color: 'var(--text-default-secondary)' }}>{t_i18n('No saved filter available.')}</Text>;
    }
    return (
      <Select value={savedFilterId} onValueChange={onSavedFilterChange}>
        <SelectTrigger aria-label={t_i18n('Saved filter')}>
          <SelectValue placeholder={t_i18n('Select a saved filter')} />
        </SelectTrigger>
        <SelectContent aria-label={t_i18n('Saved filter')}>
          {savedFilters.map((savedFilter) => (
            <SelectItem key={savedFilter.id} value={savedFilter.id}>{savedFilter.name}</SelectItem>
          ))}
        </SelectContent>
      </Select>
    );
  }
  if (mode === 'custom_view') {
    if (customViews.length === 0) {
      return <Text variant="content-compact" style={{ color: 'var(--text-default-secondary)' }}>{t_i18n('No custom view available.')}</Text>;
    }
    return (
      <Select value={customViewId} onValueChange={onCustomViewChange}>
        <SelectTrigger aria-label={t_i18n('Custom view')}>
          <SelectValue placeholder={t_i18n('Select a custom view')} />
        </SelectTrigger>
        <SelectContent aria-label={t_i18n('Custom view')}>
          {customViews.map((customView) => (
            <SelectItem key={customView.id} value={customView.id}>{`${customView.name} (${t_i18n(`entity_${customView.targetEntityType}`)})`}</SelectItem>
          ))}
        </SelectContent>
      </Select>
    );
  }
  return null;
};

const toExportData = (diff: LandscapeDiffResult): LandscapeDiffData => ({
  from: diff.from,
  to: diff.to,
  scope_entity_types: diff.scope_entity_types,
  aggregates: diff.aggregates ?? null,
  entities: diff.entities,
});

/**
 * Analyses > Landscape changes: what changed between two dates for a whole set of entities
 * (a saved filter, the entities of a custom view or custom filters).
 */
const LandscapeChanges = () => {
  const { t_i18n, fldt } = useFormatter();
  const [searchParams, setSearchParams] = useSearchParams();
  const [mode, setMode] = useState<ScopeMode>('filters');
  const [savedFilterId, setSavedFilterId] = useState('');
  const [customViewId, setCustomViewId] = useState('');
  const [entityType, setEntityType] = useState(AUTO_ENTITY_TYPE);
  const [groupBy, setGroupBy] = useState<string>('entity_type');
  const [range, setRange] = useState<DateRange>(presetRange('90d'));
  const [filters, helpers] = useFiltersState();
  const availableFilterKeys = useAvailableFilterKeysForEntityTypes(['Stix-Domain-Object']);
  const [diff, setDiff] = useState<LandscapeDiffResult | null>(null);
  const [loadingDiff, setLoadingDiff] = useState(false);
  const diffId = searchParams.get(DIFF_SEARCH_PARAM);
  const pollTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [commitRun, running] = useApiMutation<LandscapeChangesRunMutation>(landscapeChangesRunMutation);

  // Poll the background computation until it completes (the diff id is kept in the URL)
  useEffect(() => {
    let cancelled = false;
    const poll = () => {
      if (!diffId) return;
      fetchQuery<LandscapeChangesPollQuery>(landscapeChangesPollQuery, { id: diffId })
        .toPromise()
        .then((data) => {
          if (cancelled) return;
          const result = data?.landscapeDiff ?? null;
          setDiff(result);
          setLoadingDiff(false);
          if (result && (result.status === 'pending' || result.status === 'running')) {
            pollTimer.current = setTimeout(poll, POLL_INTERVAL_MS);
          }
        })
        .catch(() => {
          if (cancelled) return;
          setLoadingDiff(false);
          MESSAGING$.notifyError(t_i18n('Unable to read the landscape diff'));
        });
    };
    setDiff(null);
    setLoadingDiff(!!diffId);
    poll();
    return () => {
      cancelled = true;
      if (pollTimer.current) clearTimeout(pollTimer.current);
    };
  }, [diffId]);

  const canCompute = (mode === 'saved_filter' && !!savedFilterId)
    || (mode === 'custom_view' && !!customViewId)
    || mode === 'filters';

  const handleCompute = () => {
    const serializedFilters = mode === 'filters' && filters.filters.length + filters.filterGroups.length > 0
      ? serializeFilterGroupForBackend(filters)
      : null;
    commitRun({
      variables: {
        input: {
          from: range.from,
          to: range.to,
          group_by: groupBy as LandscapeGroupBy,
          filters: serializedFilters,
          saved_filter_id: mode === 'saved_filter' ? savedFilterId : null,
          custom_view_id: mode === 'custom_view' ? customViewId : null,
          entity_types: entityType === AUTO_ENTITY_TYPE ? null : [entityType],
        },
      },
      onCompleted: (response) => {
        const id = response.landscapeDiffRun?.id;
        if (id) {
          setSearchParams((current) => {
            const next = new URLSearchParams(current);
            next.set(DIFF_SEARCH_PARAM, id);
            return next;
          }, { replace: true });
        }
      },
    });
  };

  const isRunning = !!diff && (diff.status === 'pending' || diff.status === 'running');
  const progress = diff && diff.total > 0 ? Math.round((diff.progress / diff.total) * 100) : 0;

  return (
    <div data-testid="landscape-changes-page">
      <Breadcrumbs elements={[{ label: t_i18n('Analyses') }, { label: t_i18n('Landscape changes'), current: true }]} />
      <Box sx={{ marginBottom: 3 }}>
        <Card title={t_i18n('Scope and period')}>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            <RadioGroup
              aria-label={t_i18n('Scope')}
              orientation="horizontal"
              value={mode}
              onValueChange={(value) => setMode(value as ScopeMode)}
            >
              <Radio value="filters" label={t_i18n('Filters')} />
              <Radio value="saved_filter" label={t_i18n('Saved filter')} />
              <Radio value="custom_view" label={t_i18n('Custom view')} />
            </RadioGroup>
            <Suspense fallback={<Loader variant={LoaderVariant.inline} />}>
              <ScopeSelector
                mode={mode}
                savedFilterId={savedFilterId}
                customViewId={customViewId}
                onSavedFilterChange={setSavedFilterId}
                onCustomViewChange={setCustomViewId}
              />
            </Suspense>
            {mode === 'filters' && (
              <Box>
                <Filters
                  availableFilterKeys={availableFilterKeys}
                  helpers={helpers}
                  searchContext={{ entityTypes: ['Stix-Domain-Object'] }}
                />
                <FilterIconButton
                  filters={filters}
                  helpers={helpers}
                  redirection
                  searchContext={{ entityTypes: ['Stix-Domain-Object'] }}
                  entityTypes={['Stix-Domain-Object']}
                />
              </Box>
            )}
            <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap', alignItems: 'center' }}>
              <Select value={entityType} onValueChange={setEntityType}>
                <SelectTrigger aria-label={t_i18n('Entity types')}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent aria-label={t_i18n('Entity types')}>
                  <SelectItem value={AUTO_ENTITY_TYPE}>{t_i18n('Entity types of the scope')}</SelectItem>
                  {LANDSCAPE_ENTITY_TYPES.map((type) => (
                    <SelectItem key={type} value={type}>{t_i18n(`entity_${type}`)}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Select value={groupBy} onValueChange={setGroupBy}>
                <SelectTrigger aria-label={t_i18n('Group by')}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent aria-label={t_i18n('Group by')}>
                  <SelectItem value="entity_type">{t_i18n('Entity type')}</SelectItem>
                  <SelectItem value="relationship_type">{t_i18n('Relationship type')}</SelectItem>
                  <SelectItem value="tactic">{t_i18n('Tactic')}</SelectItem>
                </SelectContent>
              </Select>
            </Box>
            <TimeMachinePeriodSelector value={range} onChange={setRange} initialPreset="90d" />
            <Box sx={{ display: 'flex', gap: 1 }}>
              <Button onClick={handleCompute} disabled={!canCompute || running || isRunning} data-testid="landscape-changes-compute">
                {t_i18n('Compute the landscape changes')}
              </Button>
            </Box>
          </Box>
        </Card>
      </Box>
      {diffId && loadingDiff && <Loader variant={LoaderVariant.inElement} />}
      {diff && isRunning && (
        <Box sx={{ marginBottom: 3 }}>
          <Card title={t_i18n('Computing the landscape changes')}>
            <ProgressBar value={progress} aria-label={t_i18n('Landscape diff progress')} />
            <Text variant="content-compact" style={{ marginTop: 8 }}>
              {`${diff.progress} / ${diff.total} ${t_i18n('entities processed')}`}
            </Text>
          </Card>
        </Box>
      )}
      {diff && diff.status === 'failed' && (
        <Alert severity="error" sx={{ marginBottom: 3 }}>
          {t_i18n('The landscape diff could not be computed.')} {diff.error}
        </Alert>
      )}
      {diff && diff.status === 'complete' && (
        <>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 2, gap: 2, flexWrap: 'wrap' }}>
            <Text variant="title-lg">
              {t_i18n('Changes between')} {fldt(diff.from)} {t_i18n('and')} {fldt(diff.to)}
            </Text>
            <TimeMachineExportMenu
              fileName={(extension) => exportFileName('landscape_changes', diff.from, diff.to, extension)}
              buildJson={() => landscapeDiffToJson(toExportData(diff))}
              buildCsv={() => landscapeDiffToCsv(toExportData(diff), t_i18n)}
              buildHtml={() => landscapeDiffToHtml(toExportData(diff), t_i18n, fldt)}
            />
          </Box>
          <LandscapeChangesResults diff={toExportData(diff)} truncated={diff.truncated} />
        </>
      )}
      {diffId && diff === null && !loadingDiff && !running && (
        <Alert severity="info">{t_i18n('This landscape diff has expired, compute it again.')}</Alert>
      )}
    </div>
  );
};

export default LandscapeChanges;
