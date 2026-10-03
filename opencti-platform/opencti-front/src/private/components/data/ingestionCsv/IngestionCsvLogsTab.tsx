import React, { Suspense, useEffect, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery, useQueryLoader } from 'react-relay';
import Box from '@mui/material/Box';
import Stack from '@mui/material/Stack';
import CircularProgress from '@mui/material/CircularProgress';
import IconButton from '@mui/material/IconButton';
import Tooltip from '@mui/material/Tooltip';
import { RefreshOutlined } from '@mui/icons-material';
import { useFormatter } from '../../../../components/i18n';
import type { IngestionCsvLogsTabQuery } from './__generated__/IngestionCsvLogsTabQuery.graphql';
import IngestionLogTab from '../IngestionLogTab';

export const ingestionCsvLogsTabQuery = graphql`
  query IngestionCsvLogsTabQuery($id: String!) {
    ingestionCsvLogs(id: $id) {
      timestamp
      level
      type
      identifier
      message
      meta
    }
  }
`;

interface IngestionCsvLogsTabProps {
  feedId: string;
  feedName: string;
}

const IngestionCsvLogsTabBody: React.FC<{
  queryRef: PreloadedQuery<IngestionCsvLogsTabQuery>;
  feedName: string;
}> = ({ queryRef, feedName }) => {
  const data = usePreloadedQuery(ingestionCsvLogsTabQuery, queryRef);
  const logs = (data?.ingestionCsvLogs ?? []).filter((e): e is NonNullable<typeof e> => e != null);

  return <IngestionLogTab name={feedName} logHistory={logs} />;
};

// Displays the CSV feed ingestion logs directly in the feed detail page's "Logs" tab.
const IngestionCsvLogsTab: React.FC<IngestionCsvLogsTabProps> = ({ feedId, feedName }) => {
  const { t_i18n } = useFormatter();
  const [queryRef, loadQuery] = useQueryLoader<IngestionCsvLogsTabQuery>(ingestionCsvLogsTabQuery);
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
          <IngestionCsvLogsTabBody queryRef={queryRef} feedName={feedName} />
        </Suspense>
      ) : (
        <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
          <CircularProgress size={32} />
        </Box>
      )}
    </Box>
  );
};

export default IngestionCsvLogsTab;
