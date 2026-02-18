import React, { Suspense, useState, useEffect } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery, useQueryLoader } from 'react-relay';
import Drawer from '@components/common/drawer/Drawer';
import IconButton from '@mui/material/IconButton';
import Tooltip from '@mui/material/Tooltip';
import CircularProgress from '@mui/material/CircularProgress';
import Box from '@mui/material/Box';
import { RefreshOutlined } from '@mui/icons-material';
import { useFormatter } from '../../../../components/i18n';
import type { AuthProviderLogsDrawerQuery } from './__generated__/AuthProviderLogsDrawerQuery.graphql';
import AuthProviderLogTab from './AuthProviderLogTab';

export const authProviderLogsDrawerQuery = graphql`
  query AuthProviderLogsDrawerQuery($id: String!) {
    authenticationProvider(id: $id) {
      id
      name
      authLogHistory {
        timestamp
        level
        message
        type
        identifier
        meta
      }
    }
  }
`;

interface AuthProviderLogsDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  providerId: string | null;
}

/** Suspends until query is ready, then renders only the log tab. */
const AuthProviderLogsDrawerBody: React.FC<{
  queryRef: PreloadedQuery<AuthProviderLogsDrawerQuery>;
  onTitleLoaded: (providerName: string) => void;
}> = ({ queryRef, onTitleLoaded }) => {
  const data = usePreloadedQuery(authProviderLogsDrawerQuery, queryRef);
  const provider = data?.authenticationProvider;

  useEffect(() => {
    if (provider?.name) {
      onTitleLoaded(provider.name);
    }
  }, [provider?.name, onTitleLoaded]);

  if (!provider) {
    return null;
  }

  return <AuthProviderLogTab authLogHistory={provider.authLogHistory} />;
};

const AuthProviderLogsDrawerContent: React.FC<{
  queryRef: PreloadedQuery<AuthProviderLogsDrawerQuery> | null | undefined;
  onClose: () => void;
  onRefresh: () => void;
}> = ({ queryRef, onClose, onRefresh }) => {
  const { t_i18n } = useFormatter();
  const [refreshing, setRefreshing] = useState(false);
  const [title, setTitle] = useState(t_i18n('Logs'));

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
      <AuthProviderLogsDrawerBody
        queryRef={queryRef}
        onTitleLoaded={(name) => setTitle(`${t_i18n('Logs')} – ${name}`)}
      />
    </Suspense>
  ) : (
    <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
      <CircularProgress size={32} />
    </Box>
  );

  return (
    <Drawer
      title={title}
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

const AuthProviderLogsDrawer: React.FC<AuthProviderLogsDrawerProps> = ({
  isOpen,
  onClose,
  providerId,
}) => {
  const [queryRef, loadQuery] = useQueryLoader<AuthProviderLogsDrawerQuery>(authProviderLogsDrawerQuery);

  useEffect(() => {
    if (isOpen && providerId) {
      loadQuery({ id: providerId }, { fetchPolicy: 'network-only' });
    }
  }, [isOpen, providerId]);

  const handleRefresh = () => {
    if (providerId) {
      loadQuery({ id: providerId }, { fetchPolicy: 'network-only' });
    }
  };

  if (!isOpen || !providerId) {
    return null;
  }

  return (
    <AuthProviderLogsDrawerContent
      queryRef={queryRef}
      onClose={onClose}
      onRefresh={handleRefresh}
    />
  );
};

export default AuthProviderLogsDrawer;
