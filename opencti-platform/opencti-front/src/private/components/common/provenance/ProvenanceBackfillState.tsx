import React from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Link } from 'react-router';
import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import { useFormatter } from '../../../../components/i18n';
import { ProvenanceBackfillStateQuery } from './__generated__/ProvenanceBackfillStateQuery.graphql';

const provenanceBackfillStateQuery = graphql`
  query ProvenanceBackfillStateQuery {
    provenanceBackfill {
      status
      processed
      expected
      completed_at
    }
  }
`;

export const PROVENANCE_BACKFILL_LINK = '/dashboard/data/processing/tasks';

/**
 * Where the provenance backfill stands, for an element no source asserted yet, with a link to its card.
 */
const ProvenanceBackfillState = () => {
  const { t_i18n, n, fldt, rd } = useFormatter();
  const { provenanceBackfill: backfill } = useLazyLoadQuery<ProvenanceBackfillStateQuery>(provenanceBackfillStateQuery, {});
  let state: React.ReactNode;
  if (backfill.status === 'completed' && backfill.completed_at) {
    state = (
      <Tooltip>
        <TooltipTrigger asChild>
          <span tabIndex={0}>{t_i18n('Backfill completed {date}', { values: { date: rd(backfill.completed_at) } })}</span>
        </TooltipTrigger>
        <TooltipContent>{fldt(backfill.completed_at)}</TooltipContent>
      </Tooltip>
    );
  } else if (backfill.status === 'running') {
    state = t_i18n('Backfill running - {done} of {total} elements', { values: { done: n(backfill.processed), total: n(backfill.expected) } });
  } else {
    state = t_i18n('Backfill not started yet');
  }
  return (
    <Stack direction="row" gap={1} alignItems="baseline" flexWrap="wrap" data-testid="provenance-backfill-state">
      <Typography variant="body2" color="textSecondary">{state}</Typography>
      <Typography variant="body2">
        <Link to={PROVENANCE_BACKFILL_LINK}>{t_i18n('Open the backfill')}</Link>
      </Typography>
    </Stack>
  );
};

export default ProvenanceBackfillState;
