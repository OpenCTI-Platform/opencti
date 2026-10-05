import React, { Suspense, useEffect, useRef, useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { useSearchParams } from 'react-router';
import { useIntl } from 'react-intl';
import { ProgressBar, Radio, RadioGroup, Select, SelectContent, SelectItem, SelectTrigger, SelectValue, Text } from '@filigran/design-system';
import { Alert, Box } from '@mui/material';
import Button from '@common/button/Button';
import Card from '@common/card/Card';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import { fetchQuery } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useFiltersState from '../../../../utils/filters/useFiltersState';
import { serializeFilterGroupForBackend, useAvailableFilterKeysForEntityTypes } from '../../../../utils/filters/filtersUtils';
import FilterIconButton from '../../../../components/FilterIconButton';
import Filters from '../../common/lists/Filters';
import TimeMachinePeriodSelector from '../../common/time_machine/TimeMachinePeriodSelector';
import TimeMachineExportMenu from '../../common/time_machine/TimeMachineExportMenu';
import LandscapeChangesResults from '../../common/time_machine/LandscapeChangesResults';
import { hasPayloadErrors } from '../../common/time_machine/timeMachineMutations';
import {
  DateRange,
  exportFileName,
  formatDuration,
  landscapeDiffToCsv,
  landscapeDiffToHtml,
  landscapeDiffToJson,
  LandscapeDiffData,
  landscapeFailureReason,
  LANDSCAPE_POLL_INTERVAL_MS,
  landscapePollRetryDelay,
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
      filters
      saved_filter_id
      custom_view_id
      scope_entity_types
      created_at
      updated_at
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
        new_techniques { id standard_id entity_type name x_mitre_id count }
        new_techniques_count
        new_malware { id standard_id entity_type name count }
        new_malware_count
        new_tools { id standard_id entity_type name count }
        new_tools_count
        new_victims_by_sector { key label count }
        new_victims_by_country { key label count }
        new_victims_by_region { key label count }
        new_infrastructure { id standard_id entity_type name count }
        new_infrastructure_count
        new_indicators_count
        groups { key label count }
      }
      entities {
        entity_id
        standard_id
        entity_type
        name
        created_in_period
        revoked_in_period
        attributes_changed
        relationships_added
        relationships_removed
        relationships_revoked
        relationships_confidence_changed
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
type LandscapeDiffInput = LandscapeChangesRunMutation['variables']['input'];
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
export const DIFF_SEARCH_PARAM = 'diff';

interface ScopeSelectorProps {
  mode: ScopeMode;
  savedFilterId: string;
  customViewId: string;
  onSavedFilterChange: (id: string) => void;
  onCustomViewChange: (id: string) => void;
  onChooseScope: () => void;
}

// First use of a scope kind that has nothing to offer yet: what Landscape changes compares, and another scope to start with
const ScopeFirstUse = ({ message, onChooseScope }: { message: string; onChooseScope: () => void }) => {
  const { t_i18n } = useFormatter();
  return (
    <Alert
      severity="info"
      data-testid="landscape-changes-first-use"
      sx={{ alignItems: 'center' }}
      action={<Button onClick={onChooseScope}>{t_i18n('Choose a scope')}</Button>}
    >
      <Text variant="content-compact" as="p">{message}</Text>
      <Text variant="content-caption" as="p" style={{ color: 'var(--text-default-secondary)' }}>
        {t_i18n('Landscape changes compares a set of entities between two dates: new entities and relationships, new techniques, malware, tools and victims, revocations, and confidence and score changes.')}
      </Text>
    </Alert>
  );
};

const ScopeSelector = ({ mode, savedFilterId, customViewId, onSavedFilterChange, onCustomViewChange, onChooseScope }: ScopeSelectorProps) => {
  const { t_i18n } = useFormatter();
  const data = useLazyLoadQuery<LandscapeChangesScopesQuery>(landscapeChangesScopesQuery, {}, { fetchPolicy: 'store-and-network' });
  const savedFilters = (data.savedFilters?.edges ?? []).map((edge) => edge?.node).filter((node) => !!node);
  const customViews = (data.customViews?.edges ?? []).map((edge) => edge?.node).filter((node) => !!node);
  if (mode === 'saved_filter') {
    if (savedFilters.length === 0) {
      return <ScopeFirstUse message={t_i18n('No saved filter yet. Save the filters of a list to compare its entities, or start from filters.')} onChooseScope={onChooseScope} />;
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
      return <ScopeFirstUse message={t_i18n('No custom view yet. Create a custom view to compare its entities, or start from filters.')} onChooseScope={onChooseScope} />;
    }
    return (
      <Select value={customViewId} onValueChange={onCustomViewChange}>
        <SelectTrigger aria-label={t_i18n('Custom view')}>
          <SelectValue placeholder={t_i18n('Select a custom view')} />
        </SelectTrigger>
        <SelectContent aria-label={t_i18n('Custom view')}>
          {customViews.map((customView) => (
            <SelectItem key={customView.id} value={customView.id}>{t_i18n('{name} ({type})', { values: { name: customView.name, type: t_i18n(`entity_${customView.targetEntityType}`) } })}</SelectItem>
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
  group_by: diff.group_by,
  aggregates: diff.aggregates ?? null,
  entities: diff.entities,
});

/**
 * Analyses > Landscape changes: what changed between two dates for a whole set of entities
 * (a saved filter, the entities of a custom view or custom filters).
 */
const LandscapeChanges = () => {
  const { t_i18n, fldt, n } = useFormatter();
  const intl = useIntl();
  const [searchParams, setSearchParams] = useSearchParams();
  const [mode, setMode] = useState<ScopeMode>('filters');
  const [savedFilterId, setSavedFilterId] = useState('');
  const [customViewId, setCustomViewId] = useState('');
  const [entityType, setEntityType] = useState(AUTO_ENTITY_TYPE);
  const [groupBy, setGroupBy] = useState<string>('entity_type');
  const [range, setRange] = useState<DateRange>(presetRange('90d'));
  const [rangePreset, setRangePreset] = useState<string>('90d');
  const duration = (milliseconds: number) => formatDuration(milliseconds, (value, unit) => intl.formatNumber(value, { style: 'unit', unit, unitDisplay: 'long' }));
  const [filters, helpers] = useFiltersState();
  const availableFilterKeys = useAvailableFilterKeysForEntityTypes(['Stix-Domain-Object']);
  const [diff, setDiff] = useState<LandscapeDiffResult | null>(null);
  const [loadingDiff, setLoadingDiff] = useState(false);
  const diffId = searchParams.get(DIFF_SEARCH_PARAM);
  const pollTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [readFailed, setReadFailed] = useState(false);
  const retryRead = useRef<(() => void) | null>(null);
  const [commitRun, running] = useApiMutation<LandscapeChangesRunMutation>(landscapeChangesRunMutation);

  // Poll the background computation until it completes (the diff id is kept in the URL)
  useEffect(() => {
    let cancelled = false;
    let failures = 0;
    const poll = () => {
      if (!diffId) return;
      fetchQuery<LandscapeChangesPollQuery>(landscapeChangesPollQuery, { id: diffId })
        .toPromise()
        .then((data) => {
          if (cancelled) return;
          failures = 0;
          setReadFailed(false);
          const result = data?.landscapeDiff ?? null;
          setDiff(result);
          setLoadingDiff(false);
          if (result && (result.status === 'pending' || result.status === 'running')) {
            pollTimer.current = setTimeout(poll, LANDSCAPE_POLL_INTERVAL_MS);
          }
        })
        .catch(() => {
          if (cancelled) return;
          // A failed read says nothing about the computation: only a successful answer can end the polling
          failures += 1;
          setReadFailed(true);
          pollTimer.current = setTimeout(poll, landscapePollRetryDelay(failures));
        });
    };
    retryRead.current = () => {
      if (pollTimer.current) clearTimeout(pollTimer.current);
      poll();
    };
    setDiff(null);
    setReadFailed(false);
    setLoadingDiff(!!diffId);
    poll();
    return () => {
      cancelled = true;
      retryRead.current = null;
      if (pollTimer.current) clearTimeout(pollTimer.current);
    };
  }, [diffId]);

  const canCompute = (mode === 'saved_filter' && !!savedFilterId)
    || (mode === 'custom_view' && !!customViewId)
    || mode === 'filters';

  const runLandscape = (input: LandscapeDiffInput) => {
    commitRun({
      variables: { input },
      onCompleted: (response, errors) => {
        if (hasPayloadErrors(errors)) return;
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

  const handleCompute = () => {
    const serializedFilters = mode === 'filters' && filters.filters.length + filters.filterGroups.length > 0
      ? serializeFilterGroupForBackend(filters)
      : null;
    runLandscape({
      from: range.from,
      to: range.to,
      group_by: groupBy as LandscapeGroupBy,
      filters: serializedFilters,
      saved_filter_id: mode === 'saved_filter' ? savedFilterId : null,
      custom_view_id: mode === 'custom_view' ? customViewId : null,
      // A custom view compares the entity type it targets, the server derives it from the view
      entity_types: mode === 'custom_view' || entityType === AUTO_ENTITY_TYPE ? null : [entityType],
    });
  };

  // A failed diff is computed again with its own scope and period, whatever the form shows. A saved filter or a custom
  // view is sent alone: the server reads its current filters (and the target type of a custom view)
  const handleRecompute = (failed: LandscapeDiffResult, period: DateRange = { from: failed.from, to: failed.to }) => {
    const savedFilterId = failed.saved_filter_id ?? null;
    const customViewId = failed.custom_view_id ?? null;
    runLandscape({
      from: period.from,
      to: period.to,
      group_by: (failed.group_by ?? 'entity_type') as LandscapeGroupBy,
      filters: savedFilterId || customViewId ? null : (failed.filters ?? null),
      saved_filter_id: savedFilterId,
      custom_view_id: customViewId,
      entity_types: customViewId ? null : [...failed.scope_entity_types],
    });
  };

  // A scope without change during the period is compared again over the last year
  const handleWidenPeriod = (empty: LandscapeDiffResult) => {
    const wider = presetRange('365d');
    setRange(wider);
    setRangePreset('365d');
    handleRecompute(empty, wider);
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
                onChooseScope={() => setMode('filters')}
              />
            </Suspense>
            {mode === 'filters' && (
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
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
              {mode !== 'custom_view' && (
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
              )}
              <Select value={groupBy} onValueChange={setGroupBy}>
                <SelectTrigger aria-label={t_i18n('Group by')}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent aria-label={t_i18n('Group by')}>
                  <SelectItem value="entity_type">{t_i18n('Group by entity type')}</SelectItem>
                  <SelectItem value="relationship_type">{t_i18n('Group by relationship type')}</SelectItem>
                  <SelectItem value="tactic">{t_i18n('Group by tactic')}</SelectItem>
                </SelectContent>
              </Select>
            </Box>
            <TimeMachinePeriodSelector value={range} onChange={setRange} preset={rangePreset} onPresetChange={setRangePreset} />
            <Box sx={{ display: 'flex', gap: 1 }}>
              <Button onClick={handleCompute} disabled={!canCompute || running || isRunning} data-testid="landscape-changes-compute">
                {t_i18n('Compute the landscape changes')}
              </Button>
            </Box>
          </Box>
        </Card>
      </Box>
      {!diffId && (
        <Card>
          <Box
            sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2, textAlign: 'center' }}
            data-testid="landscape-changes-empty"
          >
            <Text variant="content-base" as="p">
              {t_i18n('Landscape changes compares a set of entities between two dates: new entities and relationships, new techniques, malware, tools and victims, revocations, and confidence and score changes.')}
            </Text>
            <Button variant="secondary" onClick={handleCompute} disabled={!canCompute || running}>
              {t_i18n('Compute the landscape changes')}
            </Button>
          </Box>
        </Card>
      )}
      {diffId && loadingDiff && !readFailed && <Loader variant={LoaderVariant.inElement} />}
      {diff && isRunning && (
        <Box sx={{ marginBottom: 3 }}>
          <Card title={t_i18n('Computing the landscape changes')}>
            <Box role="status" data-testid="landscape-changes-progress">
              <ProgressBar value={progress} aria-label={t_i18n('Landscape diff progress')} />
              <Text variant="content-compact" style={{ marginTop: 8 }}>
                {t_i18n('{progress} of {total} entities compared, {elapsed} elapsed', {
                  values: { progress: n(diff.progress), total: n(diff.total), elapsed: duration(Date.now() - new Date(diff.created_at).getTime()) },
                })}
              </Text>
            </Box>
          </Card>
        </Box>
      )}
      {diff && diff.status === 'failed' && (
        <Alert
          severity="error"
          sx={{ marginBottom: 3 }}
          data-testid="landscape-changes-failed"
          action={(
            <Button variant="secondary" size="small" onClick={() => handleRecompute(diff)} disabled={running}>
              {t_i18n('Compute again')}
            </Button>
          )}
        >
          {t_i18n('The landscape diff could not be computed.')} {t_i18n(landscapeFailureReason(diff.error))}
        </Alert>
      )}
      {diff && diff.status === 'complete' && (
        <>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 2, gap: 2, flexWrap: 'wrap' }}>
            <Box>
              <Text variant="title-lg" as="p">
                {t_i18n('Changes between {from} and {to}', { values: { from: fldt(diff.from), to: fldt(diff.to) } })}
              </Text>
              <Text variant="content-caption" as="p" style={{ color: 'var(--text-default-secondary)' }} data-testid="landscape-changes-status">
                {t_i18n('{total, plural, one {Compared # entity in {duration}} other {Compared # entities in {duration}}}', {
                  values: { total: diff.total, duration: duration(new Date(diff.updated_at).getTime() - new Date(diff.created_at).getTime()) },
                })}
              </Text>
            </Box>
            <TimeMachineExportMenu
              fileName={(extension) => exportFileName('landscape_changes', diff.from, diff.to, extension)}
              buildJson={() => landscapeDiffToJson(toExportData(diff))}
              buildCsv={() => landscapeDiffToCsv(toExportData(diff), t_i18n)}
              buildHtml={() => landscapeDiffToHtml(toExportData(diff), t_i18n, fldt)}
            />
          </Box>
          <LandscapeChangesResults
            diff={toExportData(diff)}
            truncated={diff.truncated}
            onWidenPeriod={rangePreset === '365d' || running ? undefined : () => handleWidenPeriod(diff)}
          />
        </>
      )}
      {diffId && readFailed && (
        <Alert
          severity="error"
          data-testid="landscape-changes-read-failed"
          sx={{ marginTop: 2 }}
          action={(
            <Button variant="secondary" size="small" onClick={() => retryRead.current?.()}>
              {t_i18n('Retry')}
            </Button>
          )}
        >
          {t_i18n('The landscape changes could not be read.')}
        </Alert>
      )}
      {diffId && diff === null && !loadingDiff && !running && (
        <Alert
          severity="info"
          data-testid="landscape-changes-expired"
          action={(
            <Button variant="secondary" size="small" onClick={handleCompute} disabled={!canCompute}>
              {t_i18n('Compute again')}
            </Button>
          )}
        >
          {t_i18n('This landscape diff has expired. Compute it again with the scope and period above.')}
        </Alert>
      )}
    </div>
  );
};

export default LandscapeChanges;
