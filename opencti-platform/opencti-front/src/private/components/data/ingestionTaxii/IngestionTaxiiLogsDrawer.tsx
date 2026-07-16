import React, { Suspense, useState, useEffect } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery, useQueryLoader } from 'react-relay';
import Drawer from '@components/common/drawer/Drawer';
import IconButton from '@mui/material/IconButton';
import Tooltip from '@mui/material/Tooltip';
import CircularProgress from '@mui/material/CircularProgress';
import Box from '@mui/material/Box';
import { RefreshOutlined } from '@mui/icons-material';
import { useFormatter } from '../../../../components/i18n';
import type { IngestionTaxiiLogsDrawerQuery } from './__generated__/IngestionTaxiiLogsDrawerQuery.graphql';
import IngestionLogTab from '../IngestionLogTab';

export const ingestionTaxiiLogsDrawerQuery = graphql`
  query IngestionTaxiiLogsDrawerQuery($id: String!) {
    ingestionTaxiiLogs(id: $id) {
      timestamp
      level
      type
      identifier
      message
      meta
    }
  }
`;

interface IngestionTaxiiLogsDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  feedId: string | null;
  feedName: string;
}

const IngestionTaxiiLogsDrawerBody: React.FC<{
  queryRef: PreloadedQuery<IngestionTaxiiLogsDrawerQuery>;
  feedName: string;
}> = ({ queryRef, feedName }) => {
  const data = usePreloadedQuery(ingestionTaxiiLogsDrawerQuery, queryRef);
  const logs = (data?.ingestionTaxiiLogs ?? []).filter((e): e is NonNullable<typeof e> => e != null);

  return <IngestionLogTab name={feedName} logHistory={logs} />;
};

const IngestionTaxiiLogsDrawerContent: React.FC<{
  queryRef: PreloadedQuery<IngestionTaxiiLogsDrawerQuery> | null | undefined;
  feedName: string;
  onClose: () => void;
  onRefresh: () => void;
}> = ({ queryRef, feedName, onClose, onRefresh }) => {
  const { t_i18n } = useFormatter();
  const [refreshing, setRefreshing] = useState(false);

  const handleRefresh = () => {
    setRefreshing(true);
    try {
      onRefresh();
    } finally {
      setRefreshing(false);
    }
  };

  const content = queryRef ? (
    <Suspense
      fallback={(
        <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
          <CircularProgress size={32} />
        </Box>
      )}
    >
      <IngestionTaxiiLogsDrawerBody queryRef={queryRef} feedName={feedName} />
    </Suspense>
  ) : (
    <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
      <CircularProgress size={32} />
    </Box>
  );

  return (
    <Drawer
      title={`${t_i18n('Logs')} – ${feedName}`}
      open
      onClose={onClose}
      header={(
        <Tooltip title={t_i18n('Refresh')}>
          <span>
            <IconButton
              size="small"
              onClick={handleRefresh}
              disabled={refreshing}
              aria-label={t_i18n('Refresh')}
            >
              <RefreshOutlined fontSize="small" sx={{ opacity: refreshing ? 0.6 : 1 }} />
            </IconButton>
          </span>
        </Tooltip>
      )}
    >
      {content}
    </Drawer>
  );
};

const IngestionTaxiiLogsDrawer: React.FC<IngestionTaxiiLogsDrawerProps> = ({
  isOpen,
  onClose,
  feedId,
  feedName,
}) => {
  const [queryRef, loadQuery] = useQueryLoader<IngestionTaxiiLogsDrawerQuery>(ingestionTaxiiLogsDrawerQuery);

  useEffect(() => {
    if (isOpen && feedId) {
      loadQuery({ id: feedId }, { fetchPolicy: 'network-only' });
    }
  }, [isOpen, feedId]);

  const handleRefresh = () => {
    if (feedId) {
      loadQuery({ id: feedId }, { fetchPolicy: 'network-only' });
    }
  };

  if (!isOpen || !feedId) {
    return null;
  }

  return (
    <IngestionTaxiiLogsDrawerContent
      queryRef={queryRef}
      feedName={feedName}
      onClose={onClose}
      onRefresh={handleRefresh}
    />
  );
};

export default IngestionTaxiiLogsDrawer;
