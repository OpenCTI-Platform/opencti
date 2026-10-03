import React, { Suspense, useEffect, useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import LinearProgress from '@mui/material/LinearProgress';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import DialogActions from '@mui/material/DialogActions';
import { RestartAltOutlined } from '@mui/icons-material';
import Button from '@common/button/Button';
import Card from '@common/card/Card';
import Dialog from '@common/dialog/Dialog';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { MESSAGING$ } from '../../../../relay/environment';
import { notifyPayloadErrors } from '../../common/provenance/provenanceUtils';
import { ProvenanceBackfillCardQuery } from './__generated__/ProvenanceBackfillCardQuery.graphql';
import { ProvenanceBackfillCardRestartMutation } from './__generated__/ProvenanceBackfillCardRestartMutation.graphql';

const provenanceBackfillCardQuery = graphql`
  query ProvenanceBackfillCardQuery {
    provenanceBackfill {
      status
      processed
      expected
      updated
      errors
      started_at
      completed_at
    }
  }
`;

const provenanceBackfillRestartMutation = graphql`
  mutation ProvenanceBackfillCardRestartMutation {
    provenanceBackfillRestart {
      status
      processed
      expected
      updated
      errors
      started_at
      completed_at
    }
  }
`;

const REFRESH_INTERVAL_MS = 10000;

const STATUS_LABELS: Record<string, string> = {
  pending: 'Pending',
  running: 'In progress',
  completed: 'Completed',
};

const ProvenanceBackfillContent = ({ fetchKey, onRefresh }: { fetchKey: number; onRefresh: () => void }) => {
  const { t_i18n, n, fldt } = useFormatter();
  const [confirmOpen, setConfirmOpen] = useState(false);
  // store-and-network keeps the current progress displayed while it refreshes
  const data = useLazyLoadQuery<ProvenanceBackfillCardQuery>(provenanceBackfillCardQuery, {}, { fetchPolicy: 'store-and-network', fetchKey });
  const [commitRestart, restartInFlight] = useApiMutation<ProvenanceBackfillCardRestartMutation>(provenanceBackfillRestartMutation);
  const backfill = data.provenanceBackfill;
  const progress = backfill.expected > 0 ? Math.min(100, Math.round((backfill.processed / backfill.expected) * 100)) : 0;
  const isCompleted = backfill.status === 'completed';
  useEffect(() => {
    if (isCompleted) return undefined;
    const interval = setInterval(onRefresh, REFRESH_INTERVAL_MS);
    return () => clearInterval(interval);
  }, [isCompleted]);
  const restart = () => {
    setConfirmOpen(false);
    commitRestart({
      variables: {},
      onCompleted: (_, errors) => {
        if (notifyPayloadErrors(errors)) return;
        onRefresh();
        MESSAGING$.notifySuccess(t_i18n('The provenance backfill will restart shortly'));
      },
    });
  };
  return (
    <Stack gap={1.5} data-testid="provenance-backfill">
      <Typography variant="body2">
        {t_i18n('The provenance of the knowledge created before provenance tracking is rebuilt in the background from the history and the works.')}
      </Typography>
      <Stack direction="row" alignItems="center" gap={2}>
        <Typography variant="h4" data-testid="provenance-backfill-status">{t_i18n(STATUS_LABELS[backfill.status] ?? backfill.status)}</Typography>
        <LinearProgress
          variant="determinate"
          value={isCompleted ? 100 : progress}
          sx={{ flex: 1, height: 8, borderRadius: 4 }}
          aria-label={t_i18n('Provenance backfill progress')}
        />
        <Typography variant="body2">{isCompleted ? '100%' : `${progress}%`}</Typography>
      </Stack>
      <Typography variant="caption">
        {t_i18n('{processed} of {expected} elements processed, {updated} updated, {errors} errors', {
          values: { processed: n(backfill.processed), expected: n(backfill.expected), updated: n(backfill.updated), errors: n(backfill.errors) },
        })}
        {backfill.completed_at ? ` - ${t_i18n('Completed on {date}', { values: { date: fldt(backfill.completed_at) } })}` : ''}
      </Typography>
      <div>
        <Button
          variant="secondary"
          size="small"
          startIcon={<RestartAltOutlined />}
          disabled={restartInFlight || backfill.status === 'running'}
          onClick={() => setConfirmOpen(true)}
        >
          {t_i18n('Restart the backfill')}
        </Button>
      </div>
      <Dialog open={confirmOpen} onClose={() => setConfirmOpen(false)} title={t_i18n('Restart the backfill')}>
        <Typography variant="body2">
          {t_i18n('The backfill is replayed from the beginning. Replays are idempotent: existing assertions are merged, never duplicated.')}
        </Typography>
        <DialogActions>
          <Button variant="secondary" onClick={() => setConfirmOpen(false)}>{t_i18n('Cancel')}</Button>
          <Button onClick={restart}>{t_i18n('Restart')}</Button>
        </DialogActions>
      </Dialog>
    </Stack>
  );
};

/**
 * Progress of the provenance backfill, refreshed while it runs.
 */
const ProvenanceBackfillCard = () => {
  const { t_i18n } = useFormatter();
  const [fetchKey, setFetchKey] = useState(0);
  return (
    <Card title={t_i18n('Provenance backfill')}>
      <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
        <ProvenanceBackfillContent fetchKey={fetchKey} onRefresh={() => setFetchKey((key) => key + 1)} />
      </Suspense>
    </Card>
  );
};

export default ProvenanceBackfillCard;
