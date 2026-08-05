import React, { Suspense, useEffect, useState } from 'react';
import { PreloadedQuery, usePreloadedQuery, useQueryLoader } from 'react-relay';
import Box from '@mui/material/Box';
import Stack from '@mui/material/Stack';
import CircularProgress from '@mui/material/CircularProgress';
import IconButton from '@mui/material/IconButton';
import Tooltip from '@mui/material/Tooltip';
import { RefreshOutlined } from '@mui/icons-material';
import { useFormatter } from '../../../../components/i18n';
import type { IngestionTaxiiLogsDrawerQuery } from './__generated__/IngestionTaxiiLogsDrawerQuery.graphql';
import { ingestionTaxiiLogsDrawerQuery } from './IngestionTaxiiLogsDrawer';
import IngestionLogTab from '../IngestionLogTab';

interface IngestionTaxiiLogsTabProps {
  feedId: string;
  feedName: string;
}

const IngestionTaxiiLogsTabBody: React.FC<{
  queryRef: PreloadedQuery<IngestionTaxiiLogsDrawerQuery>;
  feedName: string;
}> = ({ queryRef, feedName }) => {
  const data = usePreloadedQuery(ingestionTaxiiLogsDrawerQuery, queryRef);
  const logs = (data?.ingestionTaxiiLogs ?? []).filter((e): e is NonNullable<typeof e> => e != null);

  return <IngestionLogTab name={feedName} logHistory={logs} />;
};

// Same log content as the IngestionTaxiiLogsDrawer, displayed directly in
// the feed detail page's "Logs" tab instead of a side drawer.
const IngestionTaxiiLogsTab: React.FC<IngestionTaxiiLogsTabProps> = ({ feedId, feedName }) => {
  const { t_i18n } = useFormatter();
  const [queryRef, loadQuery] = useQueryLoader<IngestionTaxiiLogsDrawerQuery>(ingestionTaxiiLogsDrawerQuery);
  const [refreshing, setRefreshing] = useState(false);

  useEffect(() => {
    loadQuery({ id: feedId }, { fetchPolicy: 'network-only' });
  }, [feedId, loadQuery]);

  // Clear the refreshing state once the new query reference has arrived,
  // instead of synchronously right after triggering the (async) reload.
  useEffect(() => {
    setRefreshing(false);
  }, [queryRef]);

  const handleRefresh = () => {
    setRefreshing(true);
    loadQuery({ id: feedId }, { fetchPolicy: 'network-only' });
  };

  return (
    <Box>
      <Stack direction="row" justifyContent="flex-end" sx={{ mb: 1 }}>
        <Tooltip title={t_i18n('Refresh')}>
          <span>
            <IconButton
              size="small"
              onClick={handleRefresh}
              disabled={refreshing || !queryRef}
              aria-label={t_i18n('Refresh')}
            >
              <RefreshOutlined fontSize="small" sx={{ opacity: refreshing ? 0.6 : 1 }} />
            </IconButton>
          </span>
        </Tooltip>
      </Stack>
      {queryRef ? (
        <Suspense
          fallback={(
            <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
              <CircularProgress size={32} />
            </Box>
          )}
        >
          <IngestionTaxiiLogsTabBody queryRef={queryRef} feedName={feedName} />
        </Suspense>
      ) : (
        <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
          <CircularProgress size={32} />
        </Box>
      )}
    </Box>
  );
};

export default IngestionTaxiiLogsTab;
