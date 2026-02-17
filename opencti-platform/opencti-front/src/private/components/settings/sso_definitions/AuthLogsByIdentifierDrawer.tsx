import React, { Suspense, useState, useEffect } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery, useQueryLoader } from 'react-relay';
import Drawer from '@components/common/drawer/Drawer';
import IconButton from '@mui/material/IconButton';
import Tooltip from '@mui/material/Tooltip';
import CircularProgress from '@mui/material/CircularProgress';
import Box from '@mui/material/Box';
import { RefreshOutlined } from '@mui/icons-material';
import { useFormatter } from '../../../../components/i18n';
import type { AuthLogsByIdentifierDrawerQuery } from './__generated__/AuthLogsByIdentifierDrawerQuery.graphql';
import AuthProviderLogTab from './AuthProviderLogTab';

export const authLogsByIdentifierDrawerQuery = graphql`
  query AuthLogsByIdentifierDrawerQuery($identifier: String!) {
    authLogHistoryByIdentifier(identifier: $identifier) {
      timestamp
      level
      message
      type
      identifier
      meta
    }
  }
`;

interface AuthLogsByIdentifierDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  identifier: string | null;
  name: string;
}

/** Suspends until query is ready, then renders only the log tab. */
const AuthLogsByIdentifierDrawerBody: React.FC<{
  queryRef: PreloadedQuery<AuthLogsByIdentifierDrawerQuery>;
}> = ({ queryRef }) => {
  const data = usePreloadedQuery(authLogsByIdentifierDrawerQuery, queryRef);
  const authLogHistory = data?.authLogHistoryByIdentifier ?? [];

  return <AuthProviderLogTab authLogHistory={authLogHistory} />;
};

const AuthLogsByIdentifierDrawerContent: React.FC<{
  queryRef: PreloadedQuery<AuthLogsByIdentifierDrawerQuery> | null | undefined;
  onClose: () => void;
  onRefresh: () => void;
  name: string;
}> = ({ queryRef, onClose, onRefresh, name }) => {
  const { t_i18n } = useFormatter();
  const [refreshing, setRefreshing] = useState(false);
  const title = `${t_i18n('Logs – ')}${name}`;

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
      <AuthLogsByIdentifierDrawerBody queryRef={queryRef} />
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
      disableBackdropClose
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

/** Identifiers used by the backend for singleton auth strategies (must match providers.ts). */
export const AUTH_IDENTIFIER_HEADERS = 'Headers';
export const AUTH_IDENTIFIER_CERT = 'Cert';

const AuthLogsByIdentifierDrawer: React.FC<AuthLogsByIdentifierDrawerProps> = ({
  isOpen,
  onClose,
  identifier,
  name,
}) => {
  const [queryRef, loadQuery] = useQueryLoader<AuthLogsByIdentifierDrawerQuery>(authLogsByIdentifierDrawerQuery);

  useEffect(() => {
    if (isOpen && identifier) {
      loadQuery({ identifier });
    }
  }, [isOpen, identifier]);

  const handleRefresh = () => {
    if (identifier) {
      loadQuery({ identifier }, { fetchPolicy: 'network-only' });
    }
  };

  if (!isOpen || !identifier) {
    return null;
  }

  return (
    <AuthLogsByIdentifierDrawerContent
      queryRef={queryRef}
      onClose={onClose}
      onRefresh={handleRefresh}
      name={name}
    />
  );
};

export default AuthLogsByIdentifierDrawer;
