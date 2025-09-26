import React, { Suspense, useEffect, useRef, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery, useQueryLoader } from 'react-relay';
import { useTheme } from '@mui/material/styles';
import Box from '@mui/material/Box';
import { ConnectorLogsQuery } from '@components/data/connectors/__generated__/ConnectorLogsQuery.graphql';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';

const REFETCH_LOGS_DELAY = 5000;

const connectorLogsQuery = graphql`
  query ConnectorLogsQuery($id: String!) {
    connector(id: $id) {
      id
      manager_connector_logs
    }
  }
`;

type ConnectorLogsProps = {
  queryRef: PreloadedQuery<ConnectorLogsQuery>
  height?: string
};

const ConnectorLogs: React.FC<ConnectorLogsProps> = ({ queryRef, height = 'initial' }) => {
  const theme = useTheme();
  const { t_i18n } = useFormatter();
  const containerRef = useRef<HTMLPreElement>(null);

  const [autoScrollEnabled, setAutoScrollEnabled] = useState(true);

  const data = usePreloadedQuery<ConnectorLogsQuery>(connectorLogsQuery, queryRef);

  const handleScroll = () => {
    if (!containerRef.current) return;

    const { scrollTop, scrollHeight, clientHeight } = containerRef.current;
    // check if we are at the bottom container with a delta of 10 to be
    // sure that we are at the end
    const isAtBottom = scrollTop + clientHeight >= scrollHeight - 10;
    setAutoScrollEnabled(isAtBottom);
  };

  // on new logs and if user hasn't scrolled up, then scroll to bottom of the
  // container to see the last logs
  useEffect(() => {
    if (containerRef.current && autoScrollEnabled) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [data.connector?.manager_connector_logs, autoScrollEnabled]);

  return (
    <Box sx={{ height }}>
      <pre
        ref={containerRef}
        onScroll={handleScroll}
        style={{
          height: '100%',
          overflowX: 'scroll',
          overflowY: 'auto',
          paddingBottom: theme.spacing(2),
          backgroundColor: theme.palette.background.paper,
          padding: theme.spacing(2),
          borderRadius: 4,
          border: `1px solid ${theme.palette.divider}`,
        }}
      >
        {data.connector?.manager_connector_logs?.join('\n') || t_i18n('No logs available')}
      </pre>
    </Box>
  );
};

const ConnectorLogsWrapper: React.FC<{ connectorId: string; height?: string }> = ({ connectorId, height }) => {
  const [queryRef, loadQuery, disposeQuery] = useQueryLoader<ConnectorLogsQuery>(connectorLogsQuery);

  useEffect(() => {
    loadQuery({ id: connectorId });
    return () => disposeQuery();
  }, [connectorId, loadQuery, disposeQuery]);

  useEffect(() => {
    let interval: NodeJS.Timeout;

    if (queryRef) {
      interval = setInterval(() => {
        loadQuery({ id: connectorId }, { fetchPolicy: 'store-and-network' });
      }, REFETCH_LOGS_DELAY);
    }

    return () => {
      if (interval) {
        clearInterval(interval);
      }
    };
  }, [queryRef, connectorId, loadQuery]);

  if (!queryRef) {
    return <Loader variant={LoaderVariant.container}/>;
  }

  return (
    <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
      <ConnectorLogs queryRef={queryRef} height={height} />
    </Suspense>
  );
};

export default ConnectorLogsWrapper;
