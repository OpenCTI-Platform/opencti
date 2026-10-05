import React, { Suspense, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useIntl } from 'react-intl';
import { Box, Stack, Typography } from '@mui/material';
import { ArrowDownwardOutlined, ArrowUpwardOutlined, FileDownloadOutlined } from '@mui/icons-material';
import {
  Combobox,
  ComboboxChips,
  ComboboxClear,
  ComboboxContent,
  ComboboxControls,
  ComboboxField,
  ComboboxInput,
  ComboboxTrigger,
  IconButton,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Switch,
} from '@filigran/design-system';
import Button from '@common/button/Button';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import SearchInput from '../../../../components/SearchInput';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { fetchQuery, MESSAGING$ } from '../../../../relay/environment';
import { DefenseGapsPlatformsQuery } from './__generated__/DefenseGapsPlatformsQuery.graphql';
import { DefenseGapsLinesPaginationQuery, DefenseGapsLinesPaginationQuery$variables } from './__generated__/DefenseGapsLinesPaginationQuery.graphql';
import { DefenseGapsExportQuery$data } from './__generated__/DefenseGapsExportQuery.graphql';
import DefenseScopeToolbar from './DefenseScopeToolbar';
import DefenseGapsLines, { defenseGapsLinesQuery } from './DefenseGapsLines';
import useDefenseScope from './useDefenseScope';
import {
  DEFENSE_ACTION_LABELS,
  DEFENSE_ACTIONS,
  DEFENSE_GAPS_EXPORT_MAX,
  DEFENSE_LEVELS,
  type DefenseAction,
  defenseGapsExportFileName,
  defenseLevelLabel,
  downloadCsv,
  isThreatOverlayActive,
  toThreatScopeInput,
} from './defenseMatrix-utils';

const defenseGapsPlatformsQuery = graphql`
  query DefenseGapsPlatformsQuery {
    defensePlatforms {
      id
      name
      entity_type
      security_platform_type
    }
  }
`;

const defenseGapsExportQuery = graphql`
  query DefenseGapsExportQuery(
    $platformIds: [String!]
    $threatScope: DefenseThreatScope
    $filter: DefenseGapsFilter
    $orderBy: DefenseGapsOrdering
    $orderMode: OrderingMode
  ) {
    defenseGapExport(platformIds: $platformIds, threatScope: $threatScope, filter: $filter, orderBy: $orderBy, orderMode: $orderMode)
  }
`;

type GapsOrdering = 'priority' | 'level' | 'threat_weight' | 'x_mitre_id' | 'name' | 'platform';
const ORDERINGS: GapsOrdering[] = ['priority', 'level', 'threat_weight', 'x_mitre_id', 'name', 'platform'];
const ORDERING_LABELS: Record<GapsOrdering, string> = {
  priority: 'Priority',
  level: 'Defense level',
  threat_weight: 'Threat weight',
  x_mitre_id: 'External ID',
  name: 'Name',
  platform: 'Security platform',
};

interface LevelOption {
  value: number;
  label: string;
}
interface ActionOption {
  value: DefenseAction;
  label: string;
}

const PlatformsToolbar = ({ queryRef, scope, onScopeChange }: {
  queryRef: PreloadedQuery<DefenseGapsPlatformsQuery>;
  scope: ReturnType<typeof useDefenseScope>[0];
  onScopeChange: ReturnType<typeof useDefenseScope>[1];
}) => {
  const { defensePlatforms } = usePreloadedQuery(defenseGapsPlatformsQuery, queryRef);
  return <DefenseScopeToolbar platforms={defensePlatforms} scope={scope} onScopeChange={onScopeChange} />;
};

const DefenseGaps = () => {
  const { t_i18n } = useFormatter();
  const intl = useIntl();
  const [scope, setScope] = useDefenseScope();
  const [total, setTotal] = useState(0);
  const [levels, setLevels] = useState<number[]>([]);
  const [actions, setActions] = useState<DefenseAction[]>([]);
  const [onlyUsedByThreats, setOnlyUsedByThreats] = useState(false);
  const [search, setSearch] = useState('');
  const [orderBy, setOrderBy] = useState<GapsOrdering>('priority');
  const [orderMode, setOrderMode] = useState<'asc' | 'desc'>('desc');
  const [exporting, setExporting] = useState(false);

  const levelOptions: LevelOption[] = DEFENSE_LEVELS.map((level) => ({ value: level, label: defenseLevelLabel(t_i18n, level) }));
  const actionOptions: ActionOption[] = DEFENSE_ACTIONS.map((action) => ({ value: action, label: t_i18n(DEFENSE_ACTION_LABELS[action]) }));

  // Without threat overlay no technique is used by threats: the filter would empty the backlog
  const threatOverlay = isThreatOverlayActive(scope);
  const usedByThreatsFilter = onlyUsedByThreats && threatOverlay;
  const variables: DefenseGapsLinesPaginationQuery$variables = {
    platformIds: scope.platformIds,
    threatScope: toThreatScopeInput(scope),
    filter: {
      levels: levels.length > 0 ? levels : null,
      recommended_actions: actions.length > 0 ? actions : null,
      onlyUsedByThreats: usedByThreatsFilter,
      search: search.length > 0 ? search : null,
    },
    orderBy,
    orderMode,
    count: 50,
  };
  const platformsQueryRef = useQueryLoading<DefenseGapsPlatformsQuery>(defenseGapsPlatformsQuery, {});
  const gapsQueryRef = useQueryLoading<DefenseGapsLinesPaginationQuery>(defenseGapsLinesQuery, variables);

  const handleExport = () => {
    setExporting(true);
    const { count: _count, ...exportVariables } = variables;
    fetchQuery(defenseGapsExportQuery, exportVariables)
      .toPromise()
      .then((data) => {
        const csv = (data as DefenseGapsExportQuery$data | undefined)?.defenseGapExport;
        if (csv) {
          downloadCsv(csv, defenseGapsExportFileName(new Date()));
          if (total > DEFENSE_GAPS_EXPORT_MAX) {
            MESSAGING$.notifySuccess(t_i18n('The export holds the first {count} gaps in the current order: narrow the filters to export the others', {
              values: { count: intl.formatNumber(DEFENSE_GAPS_EXPORT_MAX) },
            }));
          }
        }
      })
      .catch(() => MESSAGING$.notifyError(t_i18n('The defense gaps export failed')))
      .finally(() => setExporting(false));
  };

  return (
    <Stack spacing={3} data-testid="defense-gaps-tab">
      {platformsQueryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <PlatformsToolbar queryRef={platformsQueryRef} scope={scope} onScopeChange={setScope} />
        </Suspense>
      )}
      <Box sx={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 2 }} data-testid="defense-gaps-toolbar">
        <SearchInput onSubmit={setSearch} />
        <Box sx={{ minWidth: 240, flex: '1 1 240px', maxWidth: 360 }}>
          <Combobox<LevelOption>
            multiple
            labelPosition="none"
            className="w-full"
            options={levelOptions}
            value={levelOptions.filter((o) => levels.includes(o.value))}
            getOptionLabel={(o) => o.label}
            isOptionEqualToValue={(a, b) => a.value === b.value}
            onValueChange={(next) => setLevels(((next as LevelOption[] | null) ?? []).map((o) => o.value))}
          >
            <ComboboxField>
              <ComboboxChips aria-label={t_i18n('Defense levels')} />
              <ComboboxInput placeholder={t_i18n('Below validated')} aria-label={t_i18n('Defense levels')} data-testid="defense-gaps-levels" />
              <ComboboxControls>
                <ComboboxClear />
                <ComboboxTrigger />
              </ComboboxControls>
            </ComboboxField>
            <ComboboxContent emptyMessage={t_i18n('No available options')} listAriaLabel={t_i18n('Defense levels')} />
          </Combobox>
        </Box>
        <Box sx={{ minWidth: 240, flex: '1 1 240px', maxWidth: 420 }}>
          <Combobox<ActionOption>
            multiple
            labelPosition="none"
            className="w-full"
            options={actionOptions}
            value={actionOptions.filter((o) => actions.includes(o.value))}
            getOptionLabel={(o) => o.label}
            isOptionEqualToValue={(a, b) => a.value === b.value}
            onValueChange={(next) => setActions(((next as ActionOption[] | null) ?? []).map((o) => o.value))}
          >
            <ComboboxField>
              <ComboboxChips aria-label={t_i18n('Recommended actions')} />
              <ComboboxInput placeholder={t_i18n('All actions')} aria-label={t_i18n('Recommended actions')} data-testid="defense-gaps-actions" />
              <ComboboxControls>
                <ComboboxClear />
                <ComboboxTrigger />
              </ComboboxControls>
            </ComboboxField>
            <ComboboxContent emptyMessage={t_i18n('No available options')} listAriaLabel={t_i18n('Recommended actions')} />
          </Combobox>
        </Box>
        <Stack direction="row" spacing={1} alignItems="center">
          <Select value={orderBy} onValueChange={(value) => setOrderBy(value as GapsOrdering)}>
            <SelectTrigger aria-label={t_i18n('Sort by')} style={{ width: 180 }}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent aria-label={t_i18n('Sort by')}>
              {ORDERINGS.map((ordering) => (
                <SelectItem key={ordering} value={ordering}>{t_i18n(ORDERING_LABELS[ordering])}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          <IconButton
            size="md"
            priority="tertiary"
            aria-label={orderMode === 'asc' ? t_i18n('Ascending order') : t_i18n('Descending order')}
            onClick={() => setOrderMode(orderMode === 'asc' ? 'desc' : 'asc')}
            icon={orderMode === 'asc' ? <ArrowUpwardOutlined fontSize="small" /> : <ArrowDownwardOutlined fontSize="small" />}
          />
        </Stack>
        <Stack direction="row" spacing={1} alignItems="center">
          <Switch
            label={t_i18n('Only techniques used by threats')}
            checked={usedByThreatsFilter}
            disabled={!threatOverlay}
            onCheckedChange={(checked) => setOnlyUsedByThreats(checked)}
            aria-describedby={threatOverlay ? undefined : 'defense-gaps-only-threats-reason'}
            data-testid="defense-gaps-only-threats"
          />
          {!threatOverlay && (
            <Typography id="defense-gaps-only-threats-reason" variant="caption" color="text.secondary" noWrap>
              {t_i18n('Choose threats in the scope first')}
            </Typography>
          )}
        </Stack>
        <Stack direction="row" spacing={1} sx={{ marginLeft: 'auto' }}>
          <Button
            variant="secondary"
            startIcon={<FileDownloadOutlined fontSize="small" />}
            onClick={handleExport}
            disabled={exporting}
            data-testid="defense-gaps-export"
          >
            {t_i18n('Export CSV')}
          </Button>
        </Stack>
      </Box>
      {gapsQueryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <DefenseGapsLines queryRef={gapsQueryRef} scope={scope} onlyUsedByThreats={usedByThreatsFilter} onTotalChange={setTotal} />
        </Suspense>
      )}
    </Stack>
  );
};

export default DefenseGaps;
