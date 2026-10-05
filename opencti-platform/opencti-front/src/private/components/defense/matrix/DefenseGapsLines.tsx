import React, { useEffect, useMemo, useState } from 'react';
import { graphql, PreloadedQuery, usePaginationFragment, usePreloadedQuery } from 'react-relay';
import { Link } from 'react-router';
import { Box, Stack, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Typography } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import { Checkbox, Chip, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import type { Theme } from '../../../../components/Theme';
import Button from '@common/button/Button';
import Card from '../../../../components/common/card/Card';
import { useFormatter } from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { DefenseGapsLinesPaginationQuery } from './__generated__/DefenseGapsLinesPaginationQuery.graphql';
import { DefenseGapsLines_data$key } from './__generated__/DefenseGapsLines_data.graphql';
import { DefenseGapsLinesRefetchQuery } from './__generated__/DefenseGapsLinesRefetchQuery.graphql';
import DefenseValidationDialog from './DefenseValidationDialog';
import DefenseTechniqueDrawer from './DefenseTechniqueDrawer';
import {
  DEFENSE_ACTION_LABELS,
  DEFENSE_DETECTION_LABELS,
  DEFENSE_VALIDATION_LABELS,
  type DefenseAction,
  type DefenseDetection,
  type DefenseScopeState,
  type DefenseValidation,
  defenseLevelColor,
  defenseLevelLabel,
  MAX_VALIDATION_TECHNIQUES,
} from './defenseMatrix-utils';

const AGGREGATE_PLATFORM = 'all';

export const defenseGapsLinesQuery = graphql`
  query DefenseGapsLinesPaginationQuery(
    $platformIds: [String!]
    $threatScope: DefenseThreatScope
    $filter: DefenseGapsFilter
    $count: Int!
    $cursor: ID
    $orderBy: DefenseGapsOrdering
    $orderMode: OrderingMode
  ) {
    ...DefenseGapsLines_data
    @arguments(
      platformIds: $platformIds
      threatScope: $threatScope
      filter: $filter
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
    )
  }
`;

const defenseGapsLinesFragment = graphql`
  fragment DefenseGapsLines_data on Query
  @argumentDefinitions(
    platformIds: { type: "[String!]" }
    threatScope: { type: "DefenseThreatScope" }
    filter: { type: "DefenseGapsFilter" }
    count: { type: "Int", defaultValue: 50 }
    cursor: { type: "ID" }
    orderBy: { type: "DefenseGapsOrdering", defaultValue: priority }
    orderMode: { type: "OrderingMode", defaultValue: desc }
  ) @refetchable(queryName: "DefenseGapsLinesRefetchQuery") {
    defenseGaps(
      platformIds: $platformIds
      threatScope: $threatScope
      filter: $filter
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
    ) @connection(key: "Pagination_defenseGaps") {
      threats_count
      edges {
        node {
          id
          attack_pattern_id
          x_mitre_id
          attack_pattern_name
          platform_id
          platform {
            id
            name
            entity_type
          }
          level
          telemetry
          detection
          validated
          recommended_action
          threat_weight
          threats_count
          priority
          last_validation_requested_at
          requiredDataComponents {
            id
            name
          }
          ruleCandidates(first: 3) {
            id
            name
            pattern_type
          }
        }
      }
      pageInfo {
        endCursor
        hasNextPage
        globalCount
      }
    }
  }
`;

interface DefenseGapsLinesProps {
  queryRef: PreloadedQuery<DefenseGapsLinesPaginationQuery>;
  scope: DefenseScopeState;
  // The backlog only lists the techniques used by the threats of the scope
  onlyUsedByThreats?: boolean;
  onTotalChange?: (total: number) => void;
}

const DefenseGapsLines = ({ queryRef, scope, onlyUsedByThreats = false, onTotalChange }: DefenseGapsLinesProps) => {
  const { t_i18n, fldt, rd } = useFormatter();
  const theme = useTheme<Theme>();
  const queryData = usePreloadedQuery(defenseGapsLinesQuery, queryRef);
  const { data, hasNext, loadNext, isLoadingNext, refetch } = usePaginationFragment<DefenseGapsLinesRefetchQuery, DefenseGapsLines_data$key>(
    defenseGapsLinesFragment,
    queryData,
  );
  const gaps = useMemo(() => (data.defenseGaps?.edges ?? []).map(({ node }) => node), [data.defenseGaps?.edges]);
  const total = data.defenseGaps?.pageInfo.globalCount ?? 0;
  useEffect(() => onTotalChange?.(total), [total, onTotalChange]);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [validating, setValidating] = useState(false);
  const [technique, setTechnique] = useState<{ id: string; title: string } | null>(null);

  const selectedGaps = gaps.filter((gap) => selectedIds.has(gap.id));
  const selectedTechniques = Array.from(new Map(selectedGaps.map((gap) => [gap.attack_pattern_id, {
    id: gap.attack_pattern_id,
    name: gap.attack_pattern_name,
    x_mitre_id: gap.x_mitre_id,
  }])).values());
  // Each selected gap is validated on its own platform only, never on the platform of another selected gap
  const selectedGapTargets = selectedGaps
    .filter((gap) => gap.platform_id !== AGGREGATE_PLATFORM)
    .map((gap) => ({ attackPatternId: gap.attack_pattern_id, platformId: gap.platform_id, platformName: gap.platform?.name ?? gap.platform_id }));
  const allSelected = gaps.length > 0 && gaps.every((gap) => selectedIds.has(gap.id));
  // Individual and "Select all" selections alike: the platform refuses a larger request
  const overValidationLimit = selectedTechniques.length > MAX_VALIDATION_TECHNIQUES;

  const toggle = (id: string, checked: boolean) => {
    const next = new Set(selectedIds);
    if (checked) next.add(id);
    else next.delete(id);
    setSelectedIds(next);
  };

  return (
    <Card
      title={(
        // Sentence case: the card title capitalizes every word otherwise
        <span style={{ textTransform: 'none' }}>
          {t_i18n('{count, plural, one {# defense gap} other {# defense gaps}}', { values: { count: total } })}
        </span>
      )}
      action={(
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <Button
            disabled={selectedTechniques.length === 0 || overValidationLimit}
            onClick={() => setValidating(true)}
            aria-describedby={overValidationLimit ? 'defense-gaps-validate-limit' : undefined}
            data-testid="defense-gaps-validate"
          >
            {selectedTechniques.length === 0
              ? t_i18n('Select gaps to validate')
              : t_i18n('{count, plural, one {Validate # technique} other {Validate # techniques}}', { values: { count: selectedTechniques.length } })}
          </Button>
        </Security>
      )}
    >
      {overValidationLimit && (
        <Typography
          id="defense-gaps-validate-limit"
          variant="body2"
          color="warning.main"
          sx={{ marginBottom: 1 }}
          data-testid="defense-gaps-validate-limit"
        >
          {t_i18n('A validation request holds at most {max} techniques and {count} are selected: unselect some of them to validate.', { values: { max: MAX_VALIDATION_TECHNIQUES, count: selectedTechniques.length } })}
        </Typography>
      )}
      {gaps.length === 0 ? (
        <Typography variant="body2" color="text.secondary" data-testid="defense-gaps-empty">
          {onlyUsedByThreats && data.defenseGaps?.threats_count === 0
            ? t_i18n('No threat matches this scope: change the selected threats or the filters.')
            : t_i18n('No defense gap matches the current scope and filters.')}
        </Typography>
      ) : (
        <TableContainer>
          <Table size="small" aria-label={t_i18n('Defense gaps')} data-testid="defense-gaps-table">
            <TableHead>
              <TableRow>
                <TableCell padding="checkbox">
                  <Checkbox
                    aria-label={t_i18n('Select all')}
                    checked={allSelected}
                    onCheckedChange={(checked) => setSelectedIds(checked === true ? new Set(gaps.map((gap) => gap.id)) : new Set())}
                  />
                </TableCell>
                <TableCell>{t_i18n('Technique')}</TableCell>
                <TableCell>{t_i18n('Security platform')}</TableCell>
                <TableCell>{t_i18n('Defense level')}</TableCell>
                <TableCell>{t_i18n('Detection')}</TableCell>
                <TableCell>{t_i18n('Validation')}</TableCell>
                <TableCell align="right">{t_i18n('Threats')}</TableCell>
                <TableCell align="right">{t_i18n('Priority')}</TableCell>
                <TableCell>{t_i18n('Recommended action')}</TableCell>
                <TableCell>{t_i18n('Rule candidates')}</TableCell>
                <TableCell>{t_i18n('Last validation request')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {gaps.map((gap) => {
                const title = gap.x_mitre_id ? `[${gap.x_mitre_id}] ${gap.attack_pattern_name}` : gap.attack_pattern_name;
                return (
                  <TableRow key={gap.id} hover selected={selectedIds.has(gap.id)} data-testid={`defense-gap-${gap.attack_pattern_id}-${gap.platform_id}`}>
                    <TableCell padding="checkbox">
                      <Checkbox
                        aria-label={t_i18n('Select {name}', { values: { name: title } })}
                        checked={selectedIds.has(gap.id)}
                        onCheckedChange={(checked) => toggle(gap.id, checked === true)}
                      />
                    </TableCell>
                    <TableCell>
                      <Box
                        component="button"
                        type="button"
                        onClick={() => setTechnique({ id: gap.attack_pattern_id, title })}
                        sx={{ all: 'unset', cursor: 'pointer', color: 'primary.main', '&:focus-visible': { outline: '2px solid', outlineColor: 'primary.main' } }}
                      >
                        {title}
                      </Box>
                    </TableCell>
                    <TableCell>{gap.platform?.name ?? t_i18n('All platforms')}</TableCell>
                    <TableCell>
                      <Chip label={defenseLevelLabel(t_i18n, gap.level)} color={defenseLevelColor(theme, gap.level)} />
                    </TableCell>
                    <TableCell>
                      <Stack spacing={0.25}>
                        <span>{t_i18n(DEFENSE_DETECTION_LABELS[gap.detection as DefenseDetection])}</span>
                        <Typography variant="caption" color="text.secondary">
                          {gap.telemetry ? t_i18n('Telemetry') : t_i18n('No telemetry')}
                        </Typography>
                      </Stack>
                    </TableCell>
                    <TableCell>{t_i18n(DEFENSE_VALIDATION_LABELS[gap.validated as DefenseValidation])}</TableCell>
                    <TableCell align="right">{gap.threats_count > 0 ? `${gap.threats_count} (${gap.threat_weight})` : '0'}</TableCell>
                    <TableCell align="right">{gap.priority}</TableCell>
                    <TableCell>
                      <Stack spacing={0.25}>
                        <span>{t_i18n(DEFENSE_ACTION_LABELS[gap.recommended_action as DefenseAction])}</span>
                        {gap.recommended_action === 'add_telemetry' && gap.requiredDataComponents.length > 0 && (
                          <Typography variant="caption" color="text.secondary">
                            {gap.requiredDataComponents.slice(0, 3).map((dc) => dc.name).join(', ')}
                          </Typography>
                        )}
                      </Stack>
                    </TableCell>
                    <TableCell>
                      {gap.ruleCandidates.length === 0 ? <Typography variant="body2" color="text.secondary">{t_i18n('None')}</Typography> : (
                        <Stack spacing={0.25}>
                          {gap.ruleCandidates.map((rule) => (
                            <Link key={rule.id} to={`/dashboard/observations/indicators/${rule.id}`}>
                              {`${rule.name} (${rule.pattern_type})`}
                            </Link>
                          ))}
                        </Stack>
                      )}
                    </TableCell>
                    <TableCell sx={{ whiteSpace: 'nowrap' }}>
                      {gap.last_validation_requested_at ? (
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <span tabIndex={0} style={{ cursor: 'help' }}>{rd(gap.last_validation_requested_at)}</span>
                          </TooltipTrigger>
                          <TooltipContent>{fldt(gap.last_validation_requested_at)}</TooltipContent>
                        </Tooltip>
                      ) : <Typography variant="body2" color="text.secondary">{t_i18n('Never')}</Typography>}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </TableContainer>
      )}
      {hasNext && (
        <Box sx={{ display: 'flex', justifyContent: 'center', marginTop: 2 }}>
          <Button variant="secondary" disabled={isLoadingNext} onClick={() => loadNext(50)} data-testid="defense-gaps-load-more">
            {t_i18n('Load more')}
          </Button>
        </Box>
      )}
      <DefenseValidationDialog
        open={validating}
        onClose={() => setValidating(false)}
        onValidated={() => {
          setSelectedIds(new Set());
          refetch({}, { fetchPolicy: 'network-only' });
        }}
        techniques={selectedTechniques}
        gaps={selectedGapTargets}
        threats={scope.threatMode === 'SELECTED' ? scope.threats : []}
      />
      <DefenseTechniqueDrawer
        attackPatternId={technique?.id ?? null}
        title={technique?.title ?? ''}
        scope={scope}
        onClose={() => setTechnique(null)}
        allowValidation
      />
    </Card>
  );
};

export default DefenseGapsLines;
