import React, { useEffect, useState } from 'react';
import { fetchQuery, graphql } from 'react-relay';
import { Alert, Chip, Paper, ProgressBar, Text } from '@filigran/design-system';
import Box from '@mui/material/Box';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { environment } from '../../../../relay/environment';
import type { IrProcessingQuery, IrProcessingQuery$data } from './__generated__/IrProcessingQuery.graphql';

// Processing of a requirement: where it stands in the stream (live, catching up, paused), the progress of its catch-up,
// its lag behind the stream, its last batch and its last error. Refreshed every few seconds.

const processingQuery = graphql`
  query IrProcessingQuery($id: ID!) {
    intelligenceRequirement(id: $id) {
      id
      ir_processing_status {
        state
        progress
        cursor_at
        stream_head_at
        catchup_from_at
        lag_seconds
        lag_events
        stream_size
        active_requirements
        last_batch { at duration_ms events entered updated rescored backfilled errors }
        totals { events entered updated rescored backfilled errors }
        last_error { at message event_id }
      }
    }
  }
`;

type Status = NonNullable<IrProcessingQuery$data['intelligenceRequirement']>['ir_processing_status'];

const REFRESH_MS = 10000;

const STATE: Record<string, { label: string; severity: 'low' | 'medium' | 'info'; help: string }> = {
  live: { label: 'Live', severity: 'low', help: 'The requirement follows the stream in real time.' },
  catching_up: { label: 'Catching up', severity: 'medium', help: 'The requirement replays the history of the stream: its content is not complete yet.' },
  paused: { label: 'Paused', severity: 'info', help: 'The requirement does not read the stream: nothing enters or changes until it is active again.' },
};

const duration = (seconds: number) => {
  if (seconds < 60) return `${seconds} s`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} min`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours} h ${String(minutes % 60).padStart(2, '0')}`;
  return `${Math.round(hours / 24)} d`;
};

const Kpi = ({ label, value, detail }: { label: string; value: string; detail?: string }) => (
  <Box sx={{ minWidth: 0 }}>
    <Text as="div" variant="content-caption" style={{ opacity: 0.7 }}>{label}</Text>
    <Text as="div" variant="title-sm">{value}</Text>
    {detail && <Text as="div" variant="content-caption" style={{ opacity: 0.7 }}>{detail}</Text>}
  </Box>
);

const IrProcessing = ({ irId }: { irId: string }) => {
  const { t_i18n, fldt, n } = useFormatter();
  const [status, setStatus] = useState<Status | null>(null);
  useEffect(() => {
    let alive = true;
    const load = () => fetchQuery<IrProcessingQuery>(environment, processingQuery, { id: irId }, { fetchPolicy: 'network-only' })
      .toPromise()
      .then((data) => {
        if (alive && data?.intelligenceRequirement) setStatus(data.intelligenceRequirement.ir_processing_status);
      });
    load();
    const timer = setInterval(load, REFRESH_MS);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, [irId]);
  if (!status) return <Loader variant={LoaderVariant.inElement} />;
  const state = STATE[status.state] ?? STATE.catching_up;
  const batch = status.last_batch;
  const totals = status.totals;
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
      <Paper padding={24}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
          <Chip label={t_i18n(state.label)} severity={state.severity} />
          <Text as="span" variant="content-compact">{t_i18n(state.help)}</Text>
        </Box>
        <Text as="div" id="ir-catchup-label" variant="content-compact-bold" style={{ marginBottom: 8 }}>
          {`${t_i18n('Catch-up')} · ${status.progress} %`}
        </Text>
        <ProgressBar value={status.progress} aria-labelledby="ir-catchup-label" />
        <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 1 }}>
          <Text as="span" variant="content-caption" style={{ opacity: 0.7 }}>{`${t_i18n('From')} ${fldt(status.catchup_from_at)}`}</Text>
          <Text as="span" variant="content-caption" style={{ opacity: 0.7 }}>{`${t_i18n('Head of the stream')} ${fldt(status.stream_head_at)}`}</Text>
        </Box>
      </Paper>
      <Paper padding={24}>
        <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 3 }}>
          <Kpi
            label={t_i18n('Lag behind the stream')}
            value={status.lag_seconds <= 120 ? t_i18n('Up to date') : duration(status.lag_seconds)}
            detail={status.lag_seconds <= 120 ? undefined : `≈ ${n(status.lag_events)} ${t_i18n('events to process (estimate)')}`}
          />
          <Kpi label={t_i18n('Last event processed')} value={fldt(status.cursor_at)} />
          <Kpi label={t_i18n('Stream')} value={`${n(status.stream_size)} ${t_i18n('events')}`} detail={`${t_i18n('Head')}: ${fldt(status.stream_head_at)}`} />
          <Kpi
            label={t_i18n('Engine queue')}
            value={`${status.active_requirements} ${t_i18n('active requirements')}`}
            detail={t_i18n('processed one after the other')}
          />
        </Box>
      </Paper>
      <Paper padding={24}>
        <Text as="div" variant="content-compact-bold" style={{ marginBottom: 12 }}>{t_i18n('Last batch')}</Text>
        {batch ? (
          <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 3 }}>
            <Kpi label={t_i18n('Processed')} value={fldt(batch.at)} detail={`${t_i18n('in')} ${duration(Math.max(1, Math.round(batch.duration_ms / 1000)))}`} />
            <Kpi label={t_i18n('Events')} value={n(batch.events)} />
            <Kpi label={t_i18n('Entered')} value={n(batch.entered)} />
            <Kpi label={t_i18n('Updated')} value={n(batch.updated)} />
            <Kpi label={t_i18n('Rescored')} value={n(batch.rescored)} />
            <Kpi label={t_i18n('Brought by the second hop')} value={n(batch.backfilled)} />
          </Box>
        ) : (
          <Text as="div" variant="content-caption" style={{ opacity: 0.7 }}>{t_i18n('No batch recorded yet: the engine has not processed this requirement since its statistics exist.')}</Text>
        )}
        {totals && (
          <Text as="div" variant="content-caption" style={{ opacity: 0.7, marginTop: 12 }}>
            {`${t_i18n('Since the statistics exist')}: ${n(totals.events)} ${t_i18n('events')}, ${n(totals.entered)} ${t_i18n('entered')}, ${n(totals.updated)} ${t_i18n('updated')}, ${n(totals.rescored)} ${t_i18n('rescored')}, ${n(totals.errors)} ${t_i18n('errors')}`}
          </Text>
        )}
      </Paper>
      {status.last_error ? (
        <Alert
          severity="error"
          title={`${t_i18n('Last error')} · ${fldt(status.last_error.at)}`}
          description={`${status.last_error.message}${status.last_error.event_id ? ` (${t_i18n('event')} ${status.last_error.event_id})` : ''}`}
        />
      ) : (
        <Text as="div" variant="content-caption" style={{ opacity: 0.7 }}>{t_i18n('No error recorded.')}</Text>
      )}
    </Box>
  );
};

export default IrProcessing;
