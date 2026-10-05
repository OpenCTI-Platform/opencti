import React, { Suspense, useCallback, useEffect, useMemo, useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Link, useSearchParams } from 'react-router';
import { useIntl } from 'react-intl';
import { Chip, Text } from '@filigran/design-system';
import { Alert, Box, Table, TableBody, TableCell, TableHead, TableRow } from '@mui/material';
import Grid from '@mui/material/Grid2';
import { ArrowBackOutlined, ArrowForwardOutlined } from '@mui/icons-material';
import Button from '@common/button/Button';
import Card from '@common/card/Card';
import TimeMachineSummaryCard from './TimeMachineSummaryCard';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import { resolveLink } from '../../../../utils/Entity';
import { containerTypes } from '../../../../utils/hooks/useAttributes';
import TimeMachineValues from './TimeMachineValues';
import TimeMachineDate from './TimeMachineDate';
import TimeMachinePeriodSelector, { CUSTOM_PERIOD } from './TimeMachinePeriodSelector';
import TimeMachineExportMenu from './TimeMachineExportMenu';
import { useTimeMachineWarningMessage } from './EntityAsOfView';
import {
  attributeOperation,
  type AttributeOperation,
  DateRange,
  diffSummaryMeasures,
  entityDiffToCsv,
  entityDiffToHtml,
  entityDiffToJson,
  exportFileName,
  FROM_SEARCH_PARAM,
  isValidDate,
  LAST_VISIT_PRESET,
  LAST_VISIT_SEARCH_PARAM,
  presetRange,
  type TimeMachinePreset,
  TO_SEARCH_PARAM,
  toComparableRange,
} from './timeMachineUtils';
import { EntityDiffTabQuery, EntityDiffTabQuery$data } from './__generated__/EntityDiffTabQuery.graphql';
import { timeMachineSliderTimelineQuery } from './TimeMachineSlider';
import { TimeMachineSliderTimelineQuery } from './__generated__/TimeMachineSliderTimelineQuery.graphql';

// Next step of a period that starts before the retained history: the oldest change still in the history of the entity
const HistoryStartHint = ({ entityId }: { entityId: string }) => {
  const { t_i18n, fldt } = useFormatter();
  const data = useLazyLoadQuery<TimeMachineSliderTimelineQuery>(timeMachineSliderTimelineQuery, { id: entityId }, { fetchPolicy: 'store-or-network' });
  const historyStart = data.entityTimeMachineTimeline?.history_start;
  if (!historyStart) return null;
  return <>{` ${t_i18n('Pick a period starting after {date}.', { values: { date: fldt(historyStart) } })}`}</>;
};

const entityDiffTabQuery = graphql`
  query EntityDiffTabQuery($id: String!, $from: DateTime!, $to: DateTime!) {
    entityDiff(id: $id, from: $from, to: $to) {
      entity_id
      entity_type
      representative
      from
      to
      existed_at_from
      exists_at_to
      restricted
      complete
      warnings
      summary {
        attributes_changed
        relationships_added
        relationships_removed
        relationships_revoked
        relationships_confidence_changed
        container_objects_added
        container_objects_removed
        confidence_before
        confidence_after
        score_before
        score_after
        relationships_added_by_type {
          relationship_type
          count
        }
        relationships_removed_by_type {
          relationship_type
          count
        }
      }
      attributes {
        key
        label
        type
        multiple
        before { raw display entity_type deleted restricted }
        after { raw display entity_type deleted restricted }
        added { raw display entity_type deleted restricted }
        removed { raw display entity_type deleted restricted }
        changed_at
        changed_by
        changes_count
      }
      relationships {
        relationship_id
        relationship_type
        action
        at
        is_source
        target_id
        target_type
        target_name
        target_deleted
        target_restricted
        confidence_before
        confidence_after
        changed_by
      }
      relationships_truncated
      container_objects {
        object_id
        object_type
        object_name
        action
        at
        deleted
        restricted
      }
      container_objects_truncated
    }
  }
`;

type EntityDiff = NonNullable<EntityDiffTabQuery$data['entityDiff']>;

// Chip tones by meaning: success for additions, error for removals, warning for revocations
const ACTION_SEVERITIES: Record<string, 'low' | 'high' | 'medium' | 'info'> = {
  added: 'low',
  removed: 'high',
  revoked: 'medium',
  unrevoked: 'info',
  confidence_changed: 'info',
};

const OPERATION_SEVERITIES: Record<AttributeOperation, 'low' | 'high' | 'info'> = {
  added: 'low',
  removed: 'high',
  changed: 'info',
};

const useActionLabel = () => {
  const { t_i18n } = useFormatter();
  return (action: string) => {
    switch (action) {
      case 'added':
        return t_i18n('Added');
      case 'removed':
        return t_i18n('Removed');
      case 'changed':
        return t_i18n('Changed');
      case 'revoked':
        return t_i18n('Revoked');
      case 'unrevoked':
        return t_i18n('Unrevoked');
      case 'confidence_changed':
        return t_i18n('Confidence changed');
      default:
        return t_i18n('Changed');
    }
  };
};

const TargetLink = ({ id, type, name, deleted, restricted }: { id?: string | null; type?: string | null; name: string; deleted: boolean; restricted: boolean }) => {
  const { t_i18n } = useFormatter();
  if (restricted) return <span>{t_i18n('Restricted')}</span>;
  const base = type ? resolveLink(type) : null;
  if (deleted || !id || !base) {
    return <span>{deleted ? t_i18n('{name} (deleted)', { values: { name } }) : name}</span>;
  }
  return <Link to={`${base}/${id}`}>{name}</Link>;
};

const SecondaryText = ({ children }: { children: React.ReactNode }) => (
  <Text variant="content-caption" style={{ color: 'var(--text-default-secondary)' }}>{children}</Text>
);

interface EntityDiffContentProps {
  entityId: string;
  range: DateRange;
  preset: string;
  onLoaded: (diff: EntityDiff | null) => void;
  onApplyPreset: (preset: TimeMachinePreset) => void;
}

const EntityDiffContent = ({ entityId, range, preset, onLoaded, onApplyPreset }: EntityDiffContentProps) => {
  const { t_i18n, n } = useFormatter();
  const intl = useIntl();
  const actionLabel = useActionLabel();
  const warningMessage = useTimeMachineWarningMessage();
  const data = useLazyLoadQuery<EntityDiffTabQuery>(entityDiffTabQuery, { id: entityId, from: range.from, to: range.to }, { fetchPolicy: 'store-and-network' });
  const diff = data.entityDiff as EntityDiff | null | undefined;
  useEffect(() => {
    onLoaded(diff && !diff.restricted ? diff : null);
  }, [diff, onLoaded]);
  if (!diff) {
    return <Alert severity="info">{t_i18n('No data available for this period.')}</Alert>;
  }
  if (diff.restricted && diff.warnings.includes('HISTORY_NOT_RETAINED')) {
    return (
      <Alert severity="info" data-testid="time-machine-diff-history-not-retained">
        {t_i18n('The history of this entity is not retained back to the start of this period: its changes cannot be compared.')}
        <Suspense fallback={null}>
          <HistoryStartHint entityId={entityId} />
        </Suspense>
      </Alert>
    );
  }
  if (diff.restricted) {
    return (
      <Alert severity="warning" data-testid="time-machine-diff-restricted">
        {t_i18n('During this period, the entity had markings or a sharing you do not have access to.')}
      </Alert>
    );
  }
  const { summary } = diff;
  // The relationship history of the period was capped: the removal, revocation and confidence counters are partial too
  const relationshipHistoryTruncated = diff.warnings.includes('RELATIONSHIP_HISTORY_TRUNCATED');
  const noChange = diff.attributes.length === 0 && diff.relationships.length === 0 && diff.container_objects.length === 0;
  const measures = diffSummaryMeasures(summary, containerTypes.includes(diff.entity_type));
  const changedMeasures = measures.filter((measure) => measure.changed);
  const unchangedLabels = measures.filter((measure) => !measure.changed).map((measure) => t_i18n(measure.label));
  const notSet = t_i18n('Not set');
  const transition = (before?: number | null, after?: number | null) => t_i18n('{before} -> {after}', {
    values: { before: before ?? notSet, after: after ?? notSet },
  });
  const measureValue = (key: string) => {
    switch (key) {
      case 'confidence':
        return transition(summary.confidence_before, summary.confidence_after);
      case 'score':
        return transition(summary.score_before, summary.score_after);
      case 'container_objects':
        return t_i18n('{added} added, {removed} removed', { values: { added: n(summary.container_objects_added), removed: n(summary.container_objects_removed) } });
      default:
        return n(summary[key as 'attributes_changed' | 'relationships_added' | 'relationships_removed' | 'relationships_revoked' | 'relationships_confidence_changed']);
    }
  };
  // Widen an empty period once: the last 90 days, then the last year
  let widerPreset: TimeMachinePreset | null = null;
  if (preset !== '365d') widerPreset = preset === '90d' ? '365d' : '90d';
  const showRelationshipConfidence = diff.relationships.some((relationship) => relationship.action === 'added' || relationship.action === 'confidence_changed');
  const showRelationshipAuthor = diff.relationships.some((relationship) => !!relationship.changed_by);
  const relationshipConfidence = (relationship: EntityDiff['relationships'][number]) => {
    if (relationship.action === 'confidence_changed') return transition(relationship.confidence_before, relationship.confidence_after);
    if (relationship.action === 'added') return relationship.confidence_after === null || relationship.confidence_after === undefined ? notSet : n(relationship.confidence_after);
    return null;
  };
  return (
    <Box data-testid="time-machine-diff">
      {(!diff.complete || diff.warnings.length > 0) && (
        <Alert severity="warning" sx={{ marginBottom: 2 }}>
          {diff.warnings.map((warning) => <div key={warning}>{warningMessage(warning)}</div>)}
        </Alert>
      )}
      {!diff.exists_at_to && (
        <Alert severity="info" sx={{ marginBottom: 2 }}>
          {t_i18n('This entity did not exist yet during this period.')}
        </Alert>
      )}
      {diff.exists_at_to && !diff.existed_at_from && (
        <Alert severity="info" sx={{ marginBottom: 2 }}>
          {t_i18n('This entity did not exist at the start of the period, its creation is part of the changes.')}
        </Alert>
      )}
      {noChange && changedMeasures.length === 0 ? (
        <Alert
          severity="info"
          data-testid="time-machine-diff-empty"
          sx={{ alignItems: 'center' }}
          action={widerPreset && (
            <Button variant="secondary" onClick={() => widerPreset && onApplyPreset(widerPreset)}>
              {widerPreset === '90d' ? t_i18n('Compare the last 90 days') : t_i18n('Compare the last year')}
            </Button>
          )}
        >
          {t_i18n('No change during this period.')}
        </Alert>
      ) : (
        <Box sx={{ marginBottom: 3 }} data-testid="time-machine-diff-summary">
          <Grid container spacing={2}>
            {changedMeasures.map((measure) => (
              <Grid key={measure.key} size={{ xs: 6, md: 3 }}>
                <TimeMachineSummaryCard label={t_i18n(measure.label)} value={measureValue(measure.key)} />
              </Grid>
            ))}
          </Grid>
          {unchangedLabels.length > 0 && (
            <Text variant="content-caption" as="p" style={{ color: 'var(--text-default-secondary)', marginTop: 8 }}>
              {t_i18n('Unchanged during this period: {measures}', { values: { measures: intl.formatList(unchangedLabels, { type: 'conjunction' }) } })}
            </Text>
          )}
        </Box>
      )}
      {diff.attributes.length > 0 && (
        <Box sx={{ marginBottom: 3 }}>
          <Card title={t_i18n('Attributes')}>
            <Table size="small" aria-label={t_i18n('Attribute changes')}>
              <TableHead>
                <TableRow>
                  <TableCell>{t_i18n('Field')}</TableCell>
                  <TableCell>{t_i18n('Change')}</TableCell>
                  <TableCell>{t_i18n('Before')}</TableCell>
                  <TableCell>{t_i18n('After')}</TableCell>
                  <TableCell>{t_i18n('Last change')}</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {diff.attributes.map((attribute) => {
                  const operation = attributeOperation(attribute.before, attribute.after);
                  return (
                    <TableRow key={attribute.key}>
                      <TableCell sx={{ verticalAlign: 'top', width: '18%' }}>{t_i18n(attribute.label)}</TableCell>
                      <TableCell sx={{ verticalAlign: 'top' }}>
                        <Chip label={actionLabel(operation)} severity={OPERATION_SEVERITIES[operation]} />
                      </TableCell>
                      <TableCell sx={{ verticalAlign: 'top', width: '28%' }}>
                        <TimeMachineValues
                          values={attribute.before}
                          type={attribute.type}
                          multiple={attribute.multiple}
                          tone={operation === 'added' ? undefined : 'removed'}
                          changed={attribute.multiple ? attribute.removed.map((value) => value.raw) : undefined}
                        />
                      </TableCell>
                      <TableCell sx={{ verticalAlign: 'top', width: '28%' }}>
                        {operation === 'removed' ? (
                          <Text variant="content-compact" style={{ color: 'var(--color-feedback-error-primary)' }}>{t_i18n('Removed')}</Text>
                        ) : (
                          <TimeMachineValues
                            values={attribute.after}
                            type={attribute.type}
                            multiple={attribute.multiple}
                            tone="added"
                            changed={attribute.multiple ? attribute.added.map((value) => value.raw) : undefined}
                          />
                        )}
                      </TableCell>
                      <TableCell sx={{ verticalAlign: 'top' }}>
                        {attribute.changed_at ? (
                          <>
                            <TimeMachineDate date={attribute.changed_at} />
                            <SecondaryText>
                              {attribute.changed_by
                                ? t_i18n('{count, plural, one {# change by {user}} other {# changes, the last one by {user}}}', { values: { count: attribute.changes_count, user: attribute.changed_by } })
                                : t_i18n('{count, plural, one {# change} other {# changes}}', { values: { count: attribute.changes_count } })}
                            </SecondaryText>
                          </>
                        ) : <SecondaryText>{t_i18n('Unknown')}</SecondaryText>}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </Card>
        </Box>
      )}
      {diff.relationships.length > 0 && (
        <Box sx={{ marginBottom: 3 }}>
          <Card title={t_i18n('Relationships')}>
            {(diff.relationships_truncated || relationshipHistoryTruncated) && (
              <Text variant="content-caption" as="p" style={{ color: 'var(--text-default-secondary)', marginBottom: 8 }}>
                {relationshipHistoryTruncated
                  ? t_i18n('Too many relationship changes during this period: the list only covers its most recent part, and so do the counters of removed, revoked and confidence-changed relationships.')
                  : t_i18n('Only the most recent relationship changes are listed, the counters cover the whole period.')}
              </Text>
            )}
            <Table size="small" aria-label={t_i18n('Relationship changes')}>
              <TableHead>
                <TableRow>
                  <TableCell>{t_i18n('Change')}</TableCell>
                  <TableCell>{t_i18n('Relationship')}</TableCell>
                  <TableCell>{t_i18n('Entity')}</TableCell>
                  {showRelationshipConfidence && <TableCell>{t_i18n('Confidence')}</TableCell>}
                  <TableCell>{t_i18n('Date')}</TableCell>
                  {showRelationshipAuthor && <TableCell>{t_i18n('By')}</TableCell>}
                </TableRow>
              </TableHead>
              <TableBody>
                {diff.relationships.map((relationship) => {
                  const DirectionIcon = relationship.is_source ? ArrowForwardOutlined : ArrowBackOutlined;
                  return (
                    <TableRow key={`${relationship.relationship_id}-${relationship.action}`}>
                      <TableCell>
                        <Chip label={actionLabel(relationship.action)} severity={ACTION_SEVERITIES[relationship.action] ?? 'info'} />
                      </TableCell>
                      <TableCell>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                          <DirectionIcon
                            fontSize="inherit"
                            titleAccess={relationship.is_source ? t_i18n('Outgoing relationship') : t_i18n('Incoming relationship')}
                          />
                          <span>{t_i18n(`relationship_${relationship.relationship_type}`)}</span>
                        </Box>
                      </TableCell>
                      <TableCell>
                        <TargetLink
                          id={relationship.target_id}
                          type={relationship.target_type}
                          name={relationship.target_name}
                          deleted={relationship.target_deleted}
                          restricted={relationship.target_restricted}
                        />
                      </TableCell>
                      {showRelationshipConfidence && <TableCell>{relationshipConfidence(relationship)}</TableCell>}
                      <TableCell><TimeMachineDate date={relationship.at} /></TableCell>
                      {showRelationshipAuthor && <TableCell>{relationship.changed_by ?? t_i18n('Unknown')}</TableCell>}
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </Card>
        </Box>
      )}
      {diff.container_objects.length > 0 && (
        <Card title={t_i18n('Contained objects')}>
          {diff.container_objects_truncated && (
            <Text variant="content-caption" as="p" style={{ color: 'var(--text-default-secondary)', marginBottom: 8 }}>
              {t_i18n('Only part of the contained object changes are listed, the counters cover the whole period.')}
            </Text>
          )}
          <Table size="small" aria-label={t_i18n('Contained object changes')}>
            <TableHead>
              <TableRow>
                <TableCell>{t_i18n('Change')}</TableCell>
                <TableCell>{t_i18n('Type')}</TableCell>
                <TableCell>{t_i18n('Entity')}</TableCell>
                <TableCell>{t_i18n('Date')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {diff.container_objects.map((object) => (
                <TableRow key={`${object.object_id}-${object.action}-${object.at}`}>
                  <TableCell><Chip label={actionLabel(object.action)} severity={ACTION_SEVERITIES[object.action] ?? 'info'} /></TableCell>
                  <TableCell>{object.object_type ? t_i18n(`entity_${object.object_type}`) : t_i18n('Unknown')}</TableCell>
                  <TableCell>
                    <TargetLink id={object.object_id} type={object.object_type} name={object.object_name} deleted={object.deleted} restricted={object.restricted} />
                  </TableCell>
                  <TableCell>{object.at ? <TimeMachineDate date={object.at} /> : t_i18n('Unknown')}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      )}
    </Box>
  );
};

const DiffExportMenu = ({ diff }: { diff: EntityDiff | null }) => {
  const { t_i18n, fldt } = useFormatter();
  return (
    <TimeMachineExportMenu
      entityId={diff?.entity_id}
      disabled={!diff}
      fileName={(extension) => exportFileName(`${diff?.representative ?? ''}_diff`, diff?.from ?? '', diff?.to ?? '', extension)}
      buildJson={() => (diff ? entityDiffToJson(diff) : '')}
      buildCsv={() => (diff ? entityDiffToCsv(diff, t_i18n) : '')}
      buildHtml={() => (diff ? entityDiffToHtml(diff, t_i18n, fldt) : '')}
    />
  );
};

interface EntityDiffTabProps {
  entityId: string;
}

/**
 * "Compare dates" section of the Changes tab: what changed between two dates (attributes, relationships, contained objects).
 * The period is kept in the URL so a diff can be shared or opened from the landscape changes; a link carrying the date
 * of the last visit of the user also offers it as the "Since your last visit" preset.
 */
const EntityDiffTab = ({ entityId }: EntityDiffTabProps) => {
  const { t_i18n } = useFormatter();
  const [searchParams, setSearchParams] = useSearchParams();
  const range = useMemo<DateRange>(() => {
    const from = searchParams.get(FROM_SEARCH_PARAM);
    const to = searchParams.get(TO_SEARCH_PARAM);
    const fallback = presetRange('30d');
    // An empty or reversed period (a hand-edited or future-only link) opens the default one
    return toComparableRange(isValidDate(from) ? from : fallback.from, isValidDate(to) ? to : fallback.to) ?? fallback;
  }, [searchParams]);
  const hasCompleteRange = toComparableRange(searchParams.get(FROM_SEARCH_PARAM), searchParams.get(TO_SEARCH_PARAM)) !== null;
  const lastVisit = searchParams.get(LAST_VISIT_SEARCH_PARAM);
  const extraPresets = useMemo(() => (isValidDate(lastVisit)
    ? [{ key: LAST_VISIT_PRESET, label: t_i18n('Since your last visit'), range: { from: lastVisit, to: new Date().toISOString() } }]
    : []), [lastVisit]);
  // A link carrying its period opens it as a custom period (or since the last visit), otherwise the last 30 days preset stays selected
  const [preset, setPreset] = useState(() => {
    if (!hasCompleteRange) return '30d';
    return isValidDate(lastVisit) && searchParams.get(FROM_SEARCH_PARAM) === lastVisit ? LAST_VISIT_PRESET : CUSTOM_PERIOD;
  });
  const [exportable, setExportable] = useState<EntityDiff | null>(null);
  const handleChange = useCallback((next: DateRange) => {
    setSearchParams((current) => {
      const params = new URLSearchParams(current);
      params.set(FROM_SEARCH_PARAM, next.from);
      params.set(TO_SEARCH_PARAM, next.to);
      return params;
    }, { replace: true });
  }, [setSearchParams]);
  const applyPreset = useCallback((next: TimeMachinePreset) => {
    setPreset(next);
    handleChange(presetRange(next));
  }, [handleChange]);
  // The period opened by default is written in the URL, so the comparison can be shared or reloaded as is
  useEffect(() => {
    if (!hasCompleteRange) handleChange(range);
  }, [hasCompleteRange, range, handleChange]);
  return (
    <Box data-testid="time-machine-compare">
      <Box sx={{ marginBottom: 2 }}>
        <TimeMachinePeriodSelector
          value={range}
          onChange={handleChange}
          preset={preset}
          onPresetChange={setPreset}
          extraPresets={extraPresets}
          actions={<DiffExportMenu diff={exportable} />}
        />
      </Box>
      <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
        <EntityDiffContent entityId={entityId} range={range} preset={preset} onLoaded={setExportable} onApplyPreset={applyPreset} />
      </Suspense>
    </Box>
  );
};

export default EntityDiffTab;
