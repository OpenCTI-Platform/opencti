import React, { Suspense, useMemo } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Link, useSearchParams } from 'react-router';
import { Chip, Text } from '@filigran/design-system';
import { Alert, Box, Table, TableBody, TableCell, TableHead, TableRow } from '@mui/material';
import Grid from '@mui/material/Grid2';
import Card from '@common/card/Card';
import TimeMachineSummaryCard from './TimeMachineSummaryCard';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import { resolveLink } from '../../../../utils/Entity';
import TimeMachineValues from './TimeMachineValues';
import TimeMachinePeriodSelector from './TimeMachinePeriodSelector';
import TimeMachineExportMenu from './TimeMachineExportMenu';
import { useTimeMachineWarningMessage } from './EntityAsOfView';
import { DateRange, entityDiffToCsv, entityDiffToHtml, entityDiffToJson, exportFileName, isValidDate, presetRange } from './timeMachineUtils';
import { EntityDiffTabQuery, EntityDiffTabQuery$data } from './__generated__/EntityDiffTabQuery.graphql';

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

export const FROM_SEARCH_PARAM = 'from';
export const TO_SEARCH_PARAM = 'to';

const actionSeverity = (action: string) => {
  switch (action) {
    case 'added':
      return 'info' as const;
    case 'removed':
      return 'high' as const;
    case 'revoked':
      return 'medium' as const;
    default:
      return 'neutral' as const;
  }
};

const useActionLabel = () => {
  const { t_i18n } = useFormatter();
  return (action: string) => {
    switch (action) {
      case 'added':
        return t_i18n('Added');
      case 'removed':
        return t_i18n('Removed');
      case 'revoked':
        return t_i18n('Revoked');
      case 'unrevoked':
        return t_i18n('Unrevoked');
      case 'confidence_changed':
        return t_i18n('Confidence changed');
      default:
        return action;
    }
  };
};

const delta = (before?: number | null, after?: number | null) => {
  if (before === null || before === undefined || after === null || after === undefined) return '-';
  return before === after ? `${after}` : `${before} -> ${after}`;
};

const TargetLink = ({ id, type, name, deleted, restricted }: { id?: string | null; type?: string | null; name: string; deleted: boolean; restricted: boolean }) => {
  const { t_i18n } = useFormatter();
  if (restricted) return <span>{t_i18n('Restricted')}</span>;
  const base = type ? resolveLink(type) : null;
  if (deleted || !id || !base) {
    return <span>{name}{deleted ? ` (${t_i18n('deleted')})` : ''}</span>;
  }
  return <Link to={`${base}/${id}`}>{name}</Link>;
};

const EntityDiffContent = ({ entityId, range }: { entityId: string; range: DateRange }) => {
  const { t_i18n, fldt, n } = useFormatter();
  const actionLabel = useActionLabel();
  const warningMessage = useTimeMachineWarningMessage();
  const data = useLazyLoadQuery<EntityDiffTabQuery>(entityDiffTabQuery, { id: entityId, from: range.from, to: range.to }, { fetchPolicy: 'store-and-network' });
  const diff = data.entityDiff as EntityDiff | null | undefined;
  if (!diff) {
    return <Alert severity="info">{t_i18n('No data available for this period.')}</Alert>;
  }
  if (diff.restricted) {
    return (
      <Alert severity="warning" data-testid="time-machine-diff-restricted">
        {t_i18n('During this period, the entity had markings or a sharing you do not have access to.')}
      </Alert>
    );
  }
  const { summary } = diff;
  const noChange = diff.attributes.length === 0 && diff.relationships.length === 0 && diff.container_objects.length === 0;
  return (
    <Box data-testid="time-machine-diff">
      <Box sx={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 2 }}>
        <TimeMachineExportMenu
          entityId={diff.entity_id}
          fileName={(extension) => exportFileName(`${diff.representative}_diff`, diff.from, diff.to, extension)}
          buildJson={() => entityDiffToJson(diff)}
          buildCsv={() => entityDiffToCsv(diff, t_i18n)}
          buildHtml={() => entityDiffToHtml(diff, t_i18n, fldt)}
        />
      </Box>
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
      <Grid container spacing={2} sx={{ marginBottom: 3 }}>
        <Grid size={{ xs: 6, md: 3 }}>
          <TimeMachineSummaryCard label={t_i18n('Attributes changed')} value={n(summary.attributes_changed)} />
        </Grid>
        <Grid size={{ xs: 6, md: 3 }}>
          <TimeMachineSummaryCard label={t_i18n('Relationships added')} value={n(summary.relationships_added)} />
        </Grid>
        <Grid size={{ xs: 6, md: 3 }}>
          <TimeMachineSummaryCard label={t_i18n('Relationships removed')} value={n(summary.relationships_removed)} />
        </Grid>
        <Grid size={{ xs: 6, md: 3 }}>
          <TimeMachineSummaryCard label={t_i18n('Relationships revoked')} value={n(summary.relationships_revoked)} />
        </Grid>
        <Grid size={{ xs: 6, md: 3 }}>
          <TimeMachineSummaryCard label={t_i18n('Confidence')} value={delta(summary.confidence_before, summary.confidence_after)} />
        </Grid>
        <Grid size={{ xs: 6, md: 3 }}>
          <TimeMachineSummaryCard label={t_i18n('Score')} value={delta(summary.score_before, summary.score_after)} />
        </Grid>
        <Grid size={{ xs: 6, md: 3 }}>
          <TimeMachineSummaryCard label={t_i18n('Confidence changes on relationships')} value={n(summary.relationships_confidence_changed)} />
        </Grid>
        <Grid size={{ xs: 6, md: 3 }}>
          <TimeMachineSummaryCard label={t_i18n('Contained objects')} value={`+${n(summary.container_objects_added)} / -${n(summary.container_objects_removed)}`} />
        </Grid>
      </Grid>
      {noChange && (
        <Alert severity="info" data-testid="time-machine-diff-empty">{t_i18n('No change during this period.')}</Alert>
      )}
      {diff.attributes.length > 0 && (
        <Box sx={{ marginBottom: 3 }}>
          <Card title={t_i18n('Attributes')}>
            <Table size="small" aria-label={t_i18n('Attribute changes')}>
              <TableHead>
                <TableRow>
                  <TableCell>{t_i18n('Field')}</TableCell>
                  <TableCell>{t_i18n('Before')}</TableCell>
                  <TableCell>{t_i18n('After')}</TableCell>
                  <TableCell>{t_i18n('Last change')}</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {diff.attributes.map((attribute) => (
                  <TableRow key={attribute.key}>
                    <TableCell sx={{ verticalAlign: 'top', width: '20%' }}>{t_i18n(attribute.label)}</TableCell>
                    <TableCell sx={{ verticalAlign: 'top', width: '30%' }}>
                      <TimeMachineValues values={attribute.before} type={attribute.type} multiple={attribute.multiple} />
                    </TableCell>
                    <TableCell sx={{ verticalAlign: 'top', width: '30%' }}>
                      <TimeMachineValues values={attribute.after} type={attribute.type} multiple={attribute.multiple} />
                    </TableCell>
                    <TableCell sx={{ verticalAlign: 'top' }}>
                      {attribute.changed_at ? (
                        <>
                          <Text variant="content-compact">{fldt(attribute.changed_at)}</Text>
                          <Text variant="content-caption" style={{ color: 'var(--text-default-secondary)' }}>
                            {attribute.changed_by ?? t_i18n('Unknown')} ({attribute.changes_count} {t_i18n('changes')})
                          </Text>
                        </>
                      ) : '-'}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Card>
        </Box>
      )}
      {diff.relationships.length > 0 && (
        <Box sx={{ marginBottom: 3 }}>
          <Card title={t_i18n('Relationships')}>
            {diff.relationships_truncated && (
              <Text variant="content-caption" as="p" style={{ color: 'var(--text-default-secondary)', marginBottom: 8 }}>
                {t_i18n('Only the most recent relationship changes are listed, the counters cover the whole period.')}
              </Text>
            )}
            <Table size="small" aria-label={t_i18n('Relationship changes')}>
              <TableHead>
                <TableRow>
                  <TableCell>{t_i18n('Action')}</TableCell>
                  <TableCell>{t_i18n('Relationship')}</TableCell>
                  <TableCell>{t_i18n('Entity')}</TableCell>
                  <TableCell>{t_i18n('Confidence')}</TableCell>
                  <TableCell>{t_i18n('Date')}</TableCell>
                  <TableCell>{t_i18n('By')}</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {diff.relationships.map((relationship) => (
                  <TableRow key={`${relationship.relationship_id}-${relationship.action}`}>
                    <TableCell><Chip label={actionLabel(relationship.action)} severity={actionSeverity(relationship.action)} /></TableCell>
                    <TableCell>
                      {relationship.is_source ? '' : '<- '}{t_i18n(`relationship_${relationship.relationship_type}`)}{relationship.is_source ? ' ->' : ''}
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
                    <TableCell>{relationship.action === 'confidence_changed' || relationship.action === 'added' ? delta(relationship.confidence_before, relationship.confidence_after) : '-'}</TableCell>
                    <TableCell>{fldt(relationship.at)}</TableCell>
                    <TableCell>{relationship.changed_by ?? '-'}</TableCell>
                  </TableRow>
                ))}
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
                <TableCell>{t_i18n('Action')}</TableCell>
                <TableCell>{t_i18n('Type')}</TableCell>
                <TableCell>{t_i18n('Entity')}</TableCell>
                <TableCell>{t_i18n('Date')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {diff.container_objects.map((object) => (
                <TableRow key={`${object.object_id}-${object.action}-${object.at}`}>
                  <TableCell><Chip label={actionLabel(object.action)} severity={actionSeverity(object.action)} /></TableCell>
                  <TableCell>{object.object_type ? t_i18n(`entity_${object.object_type}`) : '-'}</TableCell>
                  <TableCell>
                    <TargetLink id={object.object_id} type={object.object_type} name={object.object_name} deleted={object.deleted} restricted={object.restricted} />
                  </TableCell>
                  <TableCell>{object.at ? fldt(object.at) : '-'}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      )}
    </Box>
  );
};

interface EntityDiffTabProps {
  entityId: string;
}

/**
 * Diff tab of an entity: what changed between two dates (attributes, relationships, contained objects).
 * The period is kept in the URL so a diff can be shared or opened from the landscape changes.
 */
const EntityDiffTab = ({ entityId }: EntityDiffTabProps) => {
  const [searchParams, setSearchParams] = useSearchParams();
  const range = useMemo<DateRange>(() => {
    const from = searchParams.get(FROM_SEARCH_PARAM);
    const to = searchParams.get(TO_SEARCH_PARAM);
    const fallback = presetRange('30d');
    return {
      from: isValidDate(from) ? from : fallback.from,
      to: isValidDate(to) ? to : fallback.to,
    };
  }, [searchParams]);
  const hasExplicitRange = isValidDate(searchParams.get(FROM_SEARCH_PARAM));
  const handleChange = (next: DateRange) => {
    setSearchParams((current) => {
      const params = new URLSearchParams(current);
      params.set(FROM_SEARCH_PARAM, next.from);
      params.set(TO_SEARCH_PARAM, next.to);
      return params;
    }, { replace: true });
  };
  return (
    <Box>
      <Box sx={{ marginBottom: 2 }}>
        <TimeMachinePeriodSelector value={range} onChange={handleChange} initialPreset={hasExplicitRange ? 'custom' : '30d'} />
      </Box>
      <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
        <EntityDiffContent entityId={entityId} range={range} />
      </Suspense>
    </Box>
  );
};

export default EntityDiffTab;
