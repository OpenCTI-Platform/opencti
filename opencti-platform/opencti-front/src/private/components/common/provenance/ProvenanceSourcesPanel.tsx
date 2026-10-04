import React, { Suspense, useEffect } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery, useQueryLoader } from 'react-relay';
import type { PayloadError } from 'relay-runtime';
import { useTheme } from '@mui/styles';
import Stack from '@mui/material/Stack';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import Typography from '@mui/material/Typography';
import { CheckCircleOutlined } from '@mui/icons-material';
import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import Button from '@common/button/Button';
import Card from '@common/card/Card';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import Tag from '../../../../components/common/tag/Tag';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE, SETTINGS_SETPARAMETERS } from '../../../../utils/hooks/useGranted';
import ProvenanceBackfillState from './ProvenanceBackfillState';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import type { Theme } from '../../../../components/Theme';
import ProvenanceBadge from './ProvenanceBadge';
import ProvenanceSourceKindIcon from './ProvenanceSourceKindIcon';
import { MESSAGING$ } from '../../../../relay/environment';
import { groupConflictValues, groupProceduresByText, notifyPayloadErrors, type ProvenanceData, sortAssertionsByRecency, sourceKindLabel, warningColor } from './provenanceUtils';
import { ProvenanceSourcesPanelQuery } from './__generated__/ProvenanceSourcesPanelQuery.graphql';

export const provenanceSourcesPanelQuery = graphql`
  query ProvenanceSourcesPanelQuery($id: String!) {
    stixObjectOrStixRelationship(id: $id) {
      ... on StixCoreObject {
        id
        entity_type
        corroboration_count
        single_sourced
        has_conflicts
        last_asserted_at
        freshness_days
        freshness_stale
        freshness_stale_at
        x_opencti_assertions { source_id source_kind source_name first_asserted_at last_asserted_at assert_count confidence }
        x_opencti_conflicts { field field_label values { value_hash display adoptable source_id source_kind source_name confidence last_asserted_at } }
      }
      ... on StixCoreRelationship {
        id
        entity_type
        description
        corroboration_count
        single_sourced
        has_conflicts
        last_asserted_at
        freshness_days
        freshness_stale
        freshness_stale_at
        x_opencti_assertions { source_id source_kind source_name first_asserted_at last_asserted_at assert_count confidence }
        x_opencti_conflicts { field field_label values { value_hash display adoptable source_id source_kind source_name confidence last_asserted_at } }
        procedures { text source_id last_asserted_at }
      }
      ... on StixSightingRelationship {
        id
        entity_type
        corroboration_count
        single_sourced
        has_conflicts
        last_asserted_at
        freshness_days
        freshness_stale
        freshness_stale_at
        x_opencti_assertions { source_id source_kind source_name first_asserted_at last_asserted_at assert_count confidence }
        x_opencti_conflicts { field field_label values { value_hash display adoptable source_id source_kind source_name confidence last_asserted_at } }
      }
    }
  }
`;

const provenanceAdoptMutation = graphql`
  mutation ProvenanceSourcesPanelAdoptMutation($id: ID!, $field: String!, $valueHash: String!) {
    provenanceConflictAdopt(id: $id, field: $field, value_hash: $valueHash) {
      ... on BasicObject { id }
      ... on BasicRelationship { id }
    }
  }
`;

const provenanceDismissMutation = graphql`
  mutation ProvenanceSourcesPanelDismissMutation($id: ID!, $field: String!, $valueHash: String!) {
    provenanceConflictDismiss(id: $id, field: $field, value_hash: $valueHash) {
      ... on BasicObject { id }
      ... on BasicRelationship { id }
    }
  }
`;

const provenanceProcedureAdoptMutation = graphql`
  mutation ProvenanceSourcesPanelProcedureAdoptMutation($id: ID!, $text: String!) {
    provenanceProcedureAdopt(id: $id, text: $text) {
      ... on BasicRelationship { id }
    }
  }
`;

export const provenanceAssertMutation = graphql`
  mutation ProvenanceSourcesPanelAssertMutation($id: ID!) {
    provenanceAssert(id: $id) {
      ... on BasicObject { id }
      ... on BasicRelationship { id }
    }
  }
`;

interface ProvenanceSourcesContentProps {
  queryRef: PreloadedQuery<ProvenanceSourcesPanelQuery>;
  onChange: () => void;
}

const ProvenanceSourcesContent = ({ queryRef, onChange }: ProvenanceSourcesContentProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n, fldt, mhd, rd, smhd } = useFormatter();
  const data = usePreloadedQuery(provenanceSourcesPanelQuery, queryRef);
  const element = data.stixObjectOrStixRelationship as ProvenanceData | null;
  const [commitAdopt, adoptInFlight] = useApiMutation(provenanceAdoptMutation);
  const [commitDismiss, dismissInFlight] = useApiMutation(provenanceDismissMutation);
  const [commitProcedure, procedureInFlight] = useApiMutation(provenanceProcedureAdoptMutation);
  const [commitAssert, assertInFlight] = useApiMutation(provenanceAssertMutation);
  if (!element || !element.id) {
    return (
      <Typography variant="body2" data-testid="provenance-unavailable">
        {t_i18n('Provenance is not available: this type of element is not tracked, or its sources are restricted for your account.')}
      </Typography>
    );
  }
  const assertions = sortAssertionsByRecency(element.x_opencti_assertions);
  const conflicts = (element.x_opencti_conflicts ?? []).filter((conflict) => conflict.values.length > 0);
  const procedures = groupProceduresByText(element.procedures ?? [], assertions);
  const inFlight = adoptInFlight || dismissInFlight || procedureInFlight || assertInFlight;
  const completeWith = (successMessage: string) => (_: unknown, errors: readonly PayloadError[] | null) => {
    if (notifyPayloadErrors(errors)) return;
    onChange();
    MESSAGING$.notifySuccess(successMessage);
  };
  const onAdopt = (field: string, valueHash: string) => commitAdopt({ variables: { id: element.id, field, valueHash }, onCompleted: completeWith(t_i18n('The value has been adopted')) });
  const onDismiss = (field: string, valueHash: string) => commitDismiss({ variables: { id: element.id, field, valueHash }, onCompleted: completeWith(t_i18n('The value has been dismissed')) });
  const onAdoptProcedure = (text: string) => commitProcedure({ variables: { id: element.id, text }, onCompleted: completeWith(t_i18n('The procedure is now the description')) });
  const onAssert = () => commitAssert({ variables: { id: element.id }, onCompleted: completeWith(t_i18n('You confirmed this knowledge')) });
  return (
    <Stack gap={3} data-testid="provenance-sources-panel">
      <Stack direction="row" alignItems="center" justifyContent="space-between" gap={2} flexWrap="wrap">
        <Stack direction="row" alignItems="center" gap={1.5} flexWrap="wrap">
          <ProvenanceBadge
            corroborationCount={element.corroboration_count}
            freshnessDays={element.freshness_days}
            stale={element.freshness_stale}
            hasConflicts={element.has_conflicts}
          />
          {element.last_asserted_at && (
            <Tooltip>
              <TooltipTrigger asChild>
                <Typography variant="body2" color="textSecondary" tabIndex={0}>
                  {t_i18n('Last asserted {date}', { values: { date: rd(element.last_asserted_at) } })}
                </Typography>
              </TooltipTrigger>
              <TooltipContent>{smhd(element.last_asserted_at)}</TooltipContent>
            </Tooltip>
          )}
          {element.freshness_stale && (
            <Tag
              label={t_i18n('Stale knowledge')}
              labelTextTransform="none"
              color={theme.palette.error.main}
              tooltipTitle={element.freshness_stale_at ? t_i18n('Flagged as stale on {date}', { values: { date: fldt(element.freshness_stale_at) } }) : undefined}
            />
          )}
        </Stack>
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <Button
            variant="secondary"
            size="small"
            startIcon={<CheckCircleOutlined />}
            onClick={onAssert}
            disabled={inFlight}
            data-testid="provenance-assert"
          >
            {t_i18n('Confirm still valid')}
          </Button>
        </Security>
      </Stack>

      <Card title={t_i18n('Sources')} padding="small">
        {assertions.length === 0 ? (
          <Stack gap={0.5} data-testid="provenance-sources-panel-empty">
            <Typography variant="body2">{t_i18n('No source asserted this element yet. Its provenance is rebuilt by the provenance backfill.')}</Typography>
            <Security needs={[SETTINGS_SETPARAMETERS]}>
              <Suspense fallback={null}>
                <ProvenanceBackfillState />
              </Suspense>
            </Security>
          </Stack>
        ) : (
          <Table size="small" aria-label={t_i18n('Sources')}>
            <TableHead>
              <TableRow>
                <TableCell>{t_i18n('Source')}</TableCell>
                <TableCell>{t_i18n('Kind')}</TableCell>
                <TableCell>{t_i18n('First asserted')}</TableCell>
                <TableCell>{t_i18n('Last asserted')}</TableCell>
                <TableCell align="right">{t_i18n('Assertions')}</TableCell>
                <TableCell align="right">{t_i18n('Confidence')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {assertions.map((assertion) => (
                <TableRow key={assertion.source_id} data-testid="provenance-source-row">
                  <TableCell>
                    <Stack direction="row" alignItems="center" gap={1}>
                      <ProvenanceSourceKindIcon kind={assertion.source_kind} color="primary" />
                      <span>{assertion.source_name}</span>
                    </Stack>
                  </TableCell>
                  <TableCell>{t_i18n(sourceKindLabel(assertion.source_kind))}</TableCell>
                  <TableCell>{mhd(assertion.first_asserted_at)}</TableCell>
                  <TableCell>{mhd(assertion.last_asserted_at)}</TableCell>
                  <TableCell align="right">{assertion.assert_count}</TableCell>
                  <TableCell align="right">
                    {assertion.confidence ?? <Typography variant="caption" color="textSecondary">{t_i18n('Not recorded')}</Typography>}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
        {(element.corroboration_count ?? 0) > assertions.length && (
          <Typography variant="caption" component="p" sx={{ marginTop: 1 }} data-testid="provenance-bounded-sources">
            {t_i18n('Details are kept for {count} of the {total} sources: the earliest one and the most recently active ones.', {
              values: { count: assertions.length, total: element.corroboration_count },
            })}
          </Typography>
        )}
      </Card>

      {conflicts.length > 0 && (
        <Card title={t_i18n('Conflicting values')} padding="small">
          <Stack gap={2} data-testid="provenance-conflicts">
            {conflicts.map((conflict) => (
              <Stack key={conflict.field} gap={1}>
                <Typography variant="h4">{t_i18n(conflict.field_label ?? conflict.field)}</Typography>
                {groupConflictValues(conflict.values).map((value) => (
                  <Stack
                    key={value.value_hash}
                    direction="row"
                    alignItems="center"
                    justifyContent="space-between"
                    gap={2}
                    sx={{ borderLeft: `3px solid ${warningColor(theme)}`, paddingLeft: 1.5 }}
                    data-testid="provenance-conflict-value"
                  >
                    <Stack gap={0.5} sx={{ minWidth: 0 }}>
                      <Typography variant="body2" sx={{ wordBreak: 'break-word' }}>{value.display}</Typography>
                      {value.proposals.map((proposal) => (
                        <Stack key={proposal.source_id} direction="row" alignItems="center" gap={1} data-testid="provenance-conflict-proposal">
                          <ProvenanceSourceKindIcon kind={proposal.source_kind} />
                          <Typography variant="caption">
                            {t_i18n('Proposed by {source} on {date}', { values: { source: proposal.source_name ?? proposal.source_id, date: mhd(proposal.last_asserted_at) } })}
                            {proposal.confidence !== null && proposal.confidence !== undefined
                              ? ` - ${t_i18n('Confidence {confidence}', { values: { confidence: proposal.confidence } })}`
                              : ''}
                          </Typography>
                        </Stack>
                      ))}
                    </Stack>
                    <Security needs={[KNOWLEDGE_KNUPDATE]}>
                      <Stack direction="row" gap={1} flexShrink={0}>
                        <Button
                          size="small"
                          disabled={inFlight || !value.adoptable}
                          onClick={() => onAdopt(conflict.field, value.value_hash)}
                          title={value.adoptable ? undefined : t_i18n('This value is too large to be adopted, edit the field directly')}
                        >
                          {t_i18n('Adopt this value')}
                        </Button>
                        <Button size="small" variant="secondary" disabled={inFlight} onClick={() => onDismiss(conflict.field, value.value_hash)}>
                          {t_i18n('Dismiss')}
                        </Button>
                      </Stack>
                    </Security>
                  </Stack>
                ))}
              </Stack>
            ))}
          </Stack>
        </Card>
      )}

      {procedures.length > 0 && (
        <Card title={t_i18n('Procedures')} padding="small">
          <Stack gap={1.5} data-testid="provenance-procedures">
            {procedures.map((procedure) => {
              const isCurrent = (element.description ?? '').trim().toLowerCase() === procedure.text.trim().toLowerCase();
              return (
                <Stack key={procedure.text} direction="row" alignItems="center" justifyContent="space-between" gap={2} data-testid="provenance-procedure">
                  <Stack gap={0.5} sx={{ minWidth: 0 }}>
                    <Typography variant="body2" sx={{ wordBreak: 'break-word' }}>{procedure.text}</Typography>
                    {procedure.sourceNames.length > 0 && (
                      <Typography variant="caption" color="textSecondary">
                        {t_i18n('Asserted by {sources}', { values: { sources: procedure.sourceNames.join(', ') } })}
                      </Typography>
                    )}
                    {procedure.lastAssertedAt && <Typography variant="caption">{t_i18n('Last asserted {date}', { values: { date: mhd(procedure.lastAssertedAt) } })}</Typography>}
                  </Stack>
                  {isCurrent ? (
                    <Tag label={t_i18n('Current description')} labelTextTransform="none" />
                  ) : (
                    <Security needs={[KNOWLEDGE_KNUPDATE]}>
                      <Button size="small" variant="secondary" disabled={inFlight} onClick={() => onAdoptProcedure(procedure.text)}>
                        {t_i18n('Use as description')}
                      </Button>
                    </Security>
                  )}
                </Stack>
              );
            })}
          </Stack>
        </Card>
      )}
    </Stack>
  );
};

interface ProvenanceSourcesPanelProps {
  id: string;
  onChange?: () => void;
}

/**
 * Who said it, when, with which confidence; alternative values proposed by the sources and preserved procedures.
 */
const ProvenanceSourcesPanel = ({ id, onChange }: ProvenanceSourcesPanelProps) => {
  const [queryRef, loadQuery] = useQueryLoader<ProvenanceSourcesPanelQuery>(provenanceSourcesPanelQuery);
  useEffect(() => {
    loadQuery({ id }, { fetchPolicy: 'store-and-network' });
  }, [id]);
  const refresh = () => {
    loadQuery({ id }, { fetchPolicy: 'network-only' });
    onChange?.();
  };
  if (!queryRef) {
    return <Loader variant={LoaderVariant.inElement} />;
  }
  return (
    <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <ProvenanceSourcesContent queryRef={queryRef} onChange={refresh} />
    </Suspense>
  );
};

export default ProvenanceSourcesPanel;
