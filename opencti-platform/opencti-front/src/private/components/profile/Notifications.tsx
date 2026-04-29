import { Badge } from '@mui/material';
import Tab from '@mui/material/Tab';
import Tabs from '@mui/material/Tabs';
import React, { FunctionComponent, useMemo, useState } from 'react';
import { graphql, useLazyLoadQuery, useSubscription } from 'react-relay';
import { Navigate, Outlet, useLocation, useNavigate } from 'react-router-dom';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { useFormatter } from '../../../components/i18n';
import useAuth from '../../../utils/hooks/useAuth';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import useHelper from '../../../utils/hooks/useHelper';
import type { NotificationsUnreadNewsFeedsCountQuery } from './__generated__/NotificationsUnreadNewsFeedsCountQuery.graphql';
import { NotificationsNotificationNumberSubscription$data } from '@components/profile/__generated__/NotificationsNotificationNumberSubscription.graphql';

const notificationsUnreadNewsFeedsCountQuery = graphql`
  query NotificationsUnreadNewsFeedsCountQuery {
    myUnreadNewsFeedsCount
    myUnreadNotificationsCount
  }
`;

const notificationsNumberSubscription = graphql`
  subscription NotificationsNotificationNumberSubscription {
    notificationsNumber {
      count
    }
  }
`;

const Notifications: FunctionComponent = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  const { isXTMHubAccessible, me } = useAuth();
  const { isFeatureEnable } = useHelper();
  const isXTMHubNewsFeedEnabled = isFeatureEnable('XTMHUB_NEWS_FEED_ENABLED');
  const location = useLocation();
  const navigate = useNavigate();

  setTitle(t_i18n('Notifications'));

  const data = useLazyLoadQuery<NotificationsUnreadNewsFeedsCountQuery>(
    notificationsUnreadNewsFeedsCountQuery,
    {},
  );
  const unreadNewsFeedsCount = data.myUnreadNewsFeedsCount ?? 0;

  const [liveNotificationsCount, setLiveNotificationsCount] = useState<number | null>(null);

  const subConfig = useMemo(() => ({
    subscription: notificationsNumberSubscription,
    variables: {},
    onNext: (response: NotificationsNotificationNumberSubscription$data | null | undefined | unknown) => {
      const count = response ? (response as NotificationsNotificationNumberSubscription$data).notificationsNumber?.count : null;
      setLiveNotificationsCount(count ?? null);
    },
  }), []);
  useSubscription(subConfig);

  const unreadNotificationsCount = liveNotificationsCount !== null
    ? liveNotificationsCount
    : (data.myUnreadNotificationsCount ?? 0);

  const isUnsubscribedFromAllNewsFeeds = me.unsubscribed_news_feed_types?.includes('*') ?? false;
  const isNewsFeedTabVisible = isXTMHubAccessible && isXTMHubNewsFeedEnabled && !isUnsubscribedFromAllNewsFeeds;
  const activeTab = location.pathname.endsWith('news-feed') ? 'news-feed' : 'alerts';

  const handleTabChange = (_: React.SyntheticEvent, value: string) => {
    navigate(value);
  };

  if (!isNewsFeedTabVisible) {
    return (
      <div>
        <Breadcrumbs elements={[{ label: t_i18n('Notifications'), current: true }]} />
        {activeTab === 'news-feed' && <Navigate to="alerts" replace />}
        <Outlet />
      </div>
    );
  }

  return (
    <div>
      <Breadcrumbs elements={[{ label: t_i18n('Notifications'), current: true }]} />
      <Tabs value={activeTab} onChange={handleTabChange}>
        <Tab
          value="alerts"
          sx={{ textTransform: 'none' }}
          label={(
            <Badge color="error" variant="dot" invisible={unreadNotificationsCount === 0}>
              {t_i18n('Alerts')}
            </Badge>
          )}
        />
        <Tab
          value="news-feed"
          sx={{ textTransform: 'none' }}
          label={(
            <Badge color="error" variant="dot" invisible={unreadNewsFeedsCount === 0}>
              {t_i18n('News Feed')}
            </Badge>
          )}
        />
      </Tabs>
      <div style={{ marginTop: 20 }}>
        <Outlet />
      </div>
    </div>
  );
};

export default Notifications;
