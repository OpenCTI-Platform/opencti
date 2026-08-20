import React, { Suspense, useEffect, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery, useQueryLoader } from 'react-relay';
import Box from '@mui/material/Box';
import Stack from '@mui/material/Stack';
import CircularProgress from '@mui/material/CircularProgress';
import IconButton from '@mui/material/IconButton';
import Tooltip from '@mui/material/Tooltip';
import { RefreshOutlined } from '@mui/icons-material';
import { useFormatter } from '../../../../components/i18n';
import type { SyncLogsTabQuery } from './__generated__/SyncLogsTabQuery.graphql';
import IngestionLogTab from '../IngestionLogTab';

export const syncLogsTabQuery = graphql`
  query SyncLogsTabQuery($id: String!) {
    synchronizerLogs(id: $id) {
      timestamp
      level
      type
      identifier
      message
      meta
    }
  }
`;

interface SyncLogsTabProps {
  feedId: string;
  feedName: string;
}

const SyncLogsTabBody: React.FC<{
  queryRef: PreloadedQuery<SyncLogsTabQuery>;
  feedName: string;
}> = ({ queryRef, feedName }) => {
  const data = usePreloadedQuery(syncLogsTabQuery, queryRef);
  const logs = (data?.synchronizerLogs ?? []).filter((e): e is NonNullable<typeof e> => e != null);
  return <IngestionLogTab name={feedName} logHistory={logs} />;
};

const SyncLogsTab: React.FC<SyncLogsTabProps> = ({ feedId, feedName }) => {
  const { t_i18n } = useFormatter();
  const [queryRef, loadQuery] = useQueryLoader<SyncLogsTabQuery>(syncLogsTabQuery);
  const [refreshing, setRefreshing] = useState(false);

  useEffect(() => {
    loadQuery({ id: feedId }, { fetchPolicy: 'network-only' });
  }, [feedId, loadQuery]);

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
          <SyncLogsTabBody queryRef={queryRef} feedName={feedName} />
        </Suspense>
      ) : (
        <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
          <CircularProgress size={32} />
        </Box>
      )}
    </Box>
  );
};

export default SyncLogsTab;
