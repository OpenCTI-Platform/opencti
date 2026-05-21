import React, { FunctionComponent, useCallback, useEffect, useState } from 'react';
import { graphql } from 'react-relay';
import { requestSubscription } from '../../../relay/environment';
import { Box, IconButton, Tooltip, Typography } from '@mui/material';
import { Close, OpenInNewOutlined } from '@mui/icons-material';
import { useTheme } from '@mui/styles';
import useAuth from '../../../utils/hooks/useAuth';
import useHelper from '../../../utils/hooks/useHelper';
import NewsFeedToastItem, { NewsFeedToastData, NEWS_FEED_TOAST_WIDTH } from './NewsFeedToastItem';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';

const newsFeedToastSubscription = graphql`
  subscription NewsFeedToastManagerSubscription {
    newsFeedItem {
      id
      title
      news_feed_type
      metadata {
        key
        value
      }
    }
  }
`;

const MAX_VISIBLE_TOASTS = 5;

const NewsFeedToastManager: FunctionComponent = () => {
  const { isXTMHubAccessible, me, settings } = useAuth();
  const { isFeatureEnable } = useHelper();
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [toasts, setToasts] = useState<NewsFeedToastData[]>([]);

  const isNewsFeedFeatureEnabled = isFeatureEnable('XTMHUB_NEWS_FEED_ENABLED');
  const isAllNewsFeedUnsubscribed = me.unsubscribed_news_feed_types?.includes('*') ?? false;
  const isEnabled = isXTMHubAccessible && isNewsFeedFeatureEnabled && !isAllNewsFeedUnsubscribed;

  const handleNewsFeedItem = useCallback((data: { newsFeedItem?: NewsFeedToastData }) => {
    if (!data?.newsFeedItem) return;
    const { id, title, news_feed_type, metadata } = data.newsFeedItem;
    setToasts((prev) => {
      if (prev.some((t) => t.id === id)) return prev; // deduplicate
      return [...prev, { id, title, news_feed_type, metadata }];
    });
  }, []);

  useEffect(() => {
    if (!isEnabled) return undefined;
    const sub = requestSubscription({
      subscription: newsFeedToastSubscription,
      variables: {},
      onNext: handleNewsFeedItem,
    });
    return () => sub.dispose();
  }, [isEnabled, handleNewsFeedItem]);

  const handleDismissAll = useCallback(() => setToasts([]), []);

  if (!isEnabled || toasts.length === 0) return null;

  const xtmHubUrl = settings?.platform_xtmhub_url ?? '';
  const visibleToasts = toasts.slice(0, MAX_VISIBLE_TOASTS);
  const hiddenCount = toasts.length - visibleToasts.length;
  const libraryLink = xtmHubUrl ? `${xtmHubUrl}/app` : undefined;

  const glassStyle = {
    backgroundColor: `${theme.palette.primary.main}22`,
    backdropFilter: 'blur(8px)',
    border: `1px solid ${theme.palette.primary.main}44`,
    borderRadius: '8px',
    boxShadow: 4,
  } as const;

  return (
    <Box
      sx={{
        position: 'fixed',
        top: 80,
        right: 20,
        // zIndex below the Ariane sidebar so toasts slide underneath it when open
        zIndex: 1190,
        display: 'flex',
        flexDirection: 'column',
        gap: 1,
        pointerEvents: 'none',
        '& > *': { pointerEvents: 'all' },
      }}
    >
      {/* Dismiss-all button */}
      <Box sx={{ display: 'flex', justifyContent: 'flex-end' }}>
        <Tooltip title={t_i18n('Dismiss all')}>
          <IconButton
            onClick={handleDismissAll}
            aria-label={t_i18n('Dismiss all')}
            color="primary"
            sx={{ ...glassStyle, padding: '10px' }}
          >
            <Close sx={{ fontSize: 14, strokeWidth: 2, stroke: 'currentColor' }} />
          </IconButton>
        </Tooltip>
      </Box>

      {/* Toast items */}
      {visibleToasts.map((toast) => (
        <NewsFeedToastItem key={toast.id} item={toast} />
      ))}

      {/* Overflow banner */}
      {hiddenCount > 0 && libraryLink && (
        <Box
          sx={{
            ...glassStyle,
            padding: theme.spacing(1),
            display: 'flex',
            alignItems: 'center',
            gap: theme.spacing(1.5),
            width: NEWS_FEED_TOAST_WIDTH,
          }}
        >
          <Typography variant="caption" sx={{ fontWeight: 700, flex: 1, color: 'primary.main', ml: 1 }}>
            {t_i18n('(+{count}) Click to view all the new resources on the Hub', { values: { count: hiddenCount } })}
          </Typography>
          <Tooltip title={t_i18n('View all on XTM Hub')}>
            <IconButton
              component="a"
              href={libraryLink}
              target="_blank"
              rel="noopener noreferrer"
              size="small"
              color="primary"
              aria-label={t_i18n('View all on XTM Hub')}
            >
              <OpenInNewOutlined fontSize="small" />
            </IconButton>
          </Tooltip>
        </Box>
      )}
    </Box>
  );
};

export default NewsFeedToastManager;
