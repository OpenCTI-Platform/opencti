import React, { Suspense } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Text } from '@filigran/design-system';
import { Alert, Box, Table, TableBody, TableCell, TableHead, TableRow } from '@mui/material';
import Grid from '@mui/material/Grid2';
import Button from '@common/button/Button';
import Card from '@common/card/Card';
import { useFormatter } from '../../../../components/i18n';
import TimeMachineValues from './TimeMachineValues';
import { timeMachineSliderTimelineQuery } from './TimeMachineSlider';
import { EntityAsOfViewQuery } from './__generated__/EntityAsOfViewQuery.graphql';
import { TimeMachineSliderTimelineQuery } from './__generated__/TimeMachineSliderTimelineQuery.graphql';

const entityAsOfViewQuery = graphql`
  query EntityAsOfViewQuery($id: String!, $date: DateTime!) {
    entityAsOf(id: $id, date: $date) {
      entity_id
      entity_type
      date
      representative
      exists
      deleted
      deleted_at
      restricted
      complete
      warnings
      anchor
      anchor_date
      replayed_events
      history_start
      attributes {
        key
        label
        type
        multiple
        values {
          raw
          display
          entity_type
          deleted
          restricted
        }
      }
      relationships {
        relationship_type
        count
      }
      relationships_total
      container_objects_count
    }
  }
`;

interface EntityAsOfViewProps {
  entityId: string;
  date: string;
  onDateChange: (date: string) => void;
}

export const useTimeMachineWarningMessage = () => {
  const { t_i18n } = useFormatter();
  return (warning: string) => {
    switch (warning) {
      case 'MERGE_NOT_REVERSIBLE':
        return t_i18n('A merge happened after this date and cannot be undone, the view stops at the state right after the merge.');
      case 'REPLAY_WINDOW_EXCEEDED':
        return t_i18n('Too many changes happened after this date, the view stops at the oldest change that could be replayed.');
      case 'RELATIONSHIP_HISTORY_TRUNCATED':
        return t_i18n('Too many relationship changes to replay, the relationships only reflect the most recent part of the history.');
      case 'RELATIONSHIP_HISTORY_NOT_RETAINED':
        return t_i18n('The relationship history is not retained back to this date: the relationships shown may not reflect every change made since then.');
      case 'REPLAY_BEYOND_WINDOW':
        return t_i18n('This date is older than the replay window between two knowledge snapshots, the reconstruction relies on a long history replay.');
      case 'HISTORY_NOT_INDEXED_YET':
        return t_i18n('The latest change of this entity is still being recorded in its history, the view may not reflect it yet: open it again in a few seconds.');
      case 'DOCUMENT_CHANGED_DURING_READ':
        return t_i18n('This entity kept changing while the view was built, the view may not reflect its latest state: open it again in a few seconds.');
      default:
        return warning;
    }
  };
};

/**
 * "Go to the first recorded change" of an empty as-of view: the oldest change still in the history of the entity
 * (its creation, or the start of the history still retained), from the timeline the slider already loaded.
 * The creation date of the entity is only used without any history: its creation event is recorded just after it.
 */
const FirstChangeAction = ({ entityId, onDateChange }: { entityId: string; onDateChange: (date: string) => void }) => {
  const { t_i18n } = useFormatter();
  const data = useLazyLoadQuery<TimeMachineSliderTimelineQuery>(timeMachineSliderTimelineQuery, { id: entityId }, { fetchPolicy: 'store-or-network' });
  const timeline = data.entityTimeMachineTimeline;
  const firstChange = timeline?.history_start ?? timeline?.created_at;
  if (!firstChange) return null;
  return (
    <Button variant="secondary" onClick={() => onDateChange(firstChange)}>
      {t_i18n('Go to the first recorded change')}
    </Button>
  );
};

const EntityAsOfView = ({ entityId, date, onDateChange }: EntityAsOfViewProps) => {
  const { t_i18n, fldt, n } = useFormatter();
  const warningMessage = useTimeMachineWarningMessage();
  const data = useLazyLoadQuery<EntityAsOfViewQuery>(entityAsOfViewQuery, { id: entityId, date }, { fetchPolicy: 'store-and-network' });
  const asOf = data.entityAsOf;
  const firstChangeAction = (
    <Suspense fallback={null}>
      <FirstChangeAction entityId={entityId} onDateChange={onDateChange} />
    </Suspense>
  );
  if (!asOf) {
    return <Alert severity="info" sx={{ alignItems: 'center' }} action={firstChangeAction}>{t_i18n('No data available for this date.')}</Alert>;
  }
  if (asOf.deleted) {
    return (
      <Alert severity="warning" data-testid="time-machine-tombstone">
        {t_i18n('This entity was deleted on {date}.', { values: { date: fldt(asOf.deleted_at) } })}
      </Alert>
    );
  }
  if (!asOf.exists) {
    return (
      <Alert severity="info" data-testid="time-machine-not-existing" sx={{ alignItems: 'center' }} action={firstChangeAction}>
        {t_i18n('This entity did not exist yet on {date}.', { values: { date: fldt(asOf.date) } })}
      </Alert>
    );
  }
  if (asOf.restricted && asOf.warnings.includes('HISTORY_NOT_RETAINED')) {
    return (
      <Alert severity="info" data-testid="time-machine-history-not-retained" sx={{ alignItems: 'center' }} action={firstChangeAction}>
        {t_i18n('The history of this entity is not retained back to this date: its state at that date cannot be shown.')}
        {asOf.history_start && ` ${t_i18n('Pick a date after {date}.', { values: { date: fldt(asOf.history_start) } })}`}
      </Alert>
    );
  }
  if (asOf.restricted) {
    return (
      <Alert severity="warning" data-testid="time-machine-restricted">
        {t_i18n('At this date, the entity had markings or a sharing you do not have access to.')}
      </Alert>
    );
  }
  return (
    <Box data-testid="time-machine-as-of-view">
      {(!asOf.complete || asOf.warnings.length > 0) && (
        <Alert severity="warning" sx={{ marginBottom: 2 }}>
          {asOf.warnings.map((warning) => (
            <div key={warning}>{warningMessage(warning)}</div>
          ))}
        </Alert>
      )}
      <Grid container spacing={3}>
        <Grid size={{ xs: 12, lg: 8 }}>
          <Card title={t_i18n('Attributes')}>
            <Table size="small" aria-label={t_i18n('Attributes')}>
              <TableHead>
                <TableRow>
                  <TableCell>{t_i18n('Field')}</TableCell>
                  <TableCell>{t_i18n('Value')}</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {asOf.attributes.map((attribute) => (
                  <TableRow key={attribute.key}>
                    <TableCell sx={{ verticalAlign: 'top', width: '30%' }}>{t_i18n(attribute.label)}</TableCell>
                    <TableCell>
                      <TimeMachineValues values={attribute.values} type={attribute.type} multiple={attribute.multiple} />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Card>
        </Grid>
        <Grid size={{ xs: 12, lg: 4 }}>
          <Card title={t_i18n('Relationships')}>
            <Text variant="title-lg" as="p" style={{ marginBottom: 8 }}>{n(asOf.relationships_total)}</Text>
            <Table size="small" aria-label={t_i18n('Relationships by type')}>
              <TableBody>
                {asOf.relationships.map((relationship) => (
                  <TableRow key={relationship.relationship_type}>
                    <TableCell>{t_i18n(`relationship_${relationship.relationship_type}`)}</TableCell>
                    <TableCell align="right">{n(relationship.count)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            {asOf.container_objects_count !== null && asOf.container_objects_count !== undefined && (
              <Text variant="content-compact" style={{ marginTop: 16 }}>
                {t_i18n('{count, plural, one {# contained object} other {# contained objects}}', { values: { count: asOf.container_objects_count } })}
              </Text>
            )}
          </Card>
          <Box sx={{ marginTop: 3 }}>
            <Card title={t_i18n('Reconstruction')}>
              <Text variant="content-compact">
                {asOf.anchor === 'snapshot'
                  ? t_i18n('Rebuilt from the knowledge snapshot of {date}', { values: { date: fldt(asOf.anchor_date) } })
                  : t_i18n('Rebuilt from the current knowledge of {date}', { values: { date: fldt(asOf.anchor_date) } })}
              </Text>
              <Text variant="content-compact">
                {t_i18n('{count, plural, one {# change replayed} other {# changes replayed}}', { values: { count: asOf.replayed_events } })}
              </Text>
              {asOf.history_start && (
                <Text variant="content-compact">
                  {t_i18n('History available since {date}', { values: { date: fldt(asOf.history_start) } })}
                </Text>
              )}
            </Card>
          </Box>
        </Grid>
      </Grid>
    </Box>
  );
};

export default EntityAsOfView;
