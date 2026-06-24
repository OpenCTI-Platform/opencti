import { Badge } from '@mui/material';
import Tab from '@mui/material/Tab';
import Tabs from '@mui/material/Tabs';
import React, { FunctionComponent, useEffect, useMemo, useState } from 'react';
import { graphql, useLazyLoadQuery, useSubscription } from 'react-relay';
import { Navigate, Outlet, useMatch, useNavigate } from 'react-router-dom';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { useFormatter } from '../../../components/i18n';
import useAuth from '../../../utils/hooks/useAuth';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import { requestSubscription } from '../../../relay/environment';
import type { NotificationsUnreadNewsFeedsCountQuery } from './__generated__/NotificationsUnreadNewsFeedsCountQuery.graphql';
import { NotificationsNotificationNumberSubscription$data } from '@components/profile/__generated__/NotificationsNotificationNumberSubscription.graphql';
import { NotificationsNewsFeedNumberSubscription$data } from './__generated__/NotificationsNewsFeedNumberSubscription.graphql';

const notificationsUnreadNewsFeedsCountQuery = graphql`
  query NotificationsUnreadNewsFeedsCountQuery($skipNewsFeedsCount: Boolean!) {
    myUnreadNewsFeedsCount @skip(if: $skipNewsFeedsCount)
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

const newsFeedNumberSubscription = graphql`
  subscription NotificationsNewsFeedNumberSubscription {
    newsFeedsNumber {
      count
    }
  }
`;

const Notifications: FunctionComponent = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  const { settings, me } = useAuth();
  const isXTMHubRegistered = settings.xtm_hub_registration_status === 'registered';
  const navigate = useNavigate();

  setTitle(t_i18n('Notifications'));

  const isUnsubscribedFromAllNewsFeeds = me.unsubscribed_news_feed_types?.includes('*') ?? false;
  const isNewsFeedTabVisible = isXTMHubRegistered && !isUnsubscribedFromAllNewsFeeds;

  const data = useLazyLoadQuery<NotificationsUnreadNewsFeedsCountQuery>(
    notificationsUnreadNewsFeedsCountQuery,
    { skipNewsFeedsCount: !isNewsFeedTabVisible },
  );

  const [liveNotificationsCount, setLiveNotificationsCount] = useState<number | null>(null);
  const [liveNewsFeedsCount, setLiveNewsFeedsCount] = useState<number | null>(null);

  const subConfig = useMemo(() => ({
    subscription: notificationsNumberSubscription,
    variables: {},
    onNext: (response: NotificationsNotificationNumberSubscription$data | null | undefined | unknown) => {
      const count = response ? (response as NotificationsNotificationNumberSubscription$data).notificationsNumber?.count : null;
      setLiveNotificationsCount(count ?? null);
    },
  }), []);
  useSubscription(subConfig);

  useEffect(() => {
    if (!isNewsFeedTabVisible) return undefined;
    const sub = requestSubscription({
      subscription: newsFeedNumberSubscription,
      variables: {},
      onNext: (response: NotificationsNewsFeedNumberSubscription$data | null | undefined | unknown) => {
        const count = response ? (response as NotificationsNewsFeedNumberSubscription$data).newsFeedsNumber?.count : null;
        setLiveNewsFeedsCount(count ?? null);
      },
    });
    return () => sub.dispose();
  }, [isNewsFeedTabVisible]);

  const unreadNotificationsCount = liveNotificationsCount !== null
    ? liveNotificationsCount
    : (data.myUnreadNotificationsCount ?? 0);
  const unreadNewsFeedsCount = liveNewsFeedsCount !== null
    ? liveNewsFeedsCount
    : (data.myUnreadNewsFeedsCount ?? 0);

  const activeTab = useMatch('/dashboard/profile/notifications/news-feed') ? 'news-feed' : 'alerts';

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
            <Badge color="error" badgeContent={unreadNotificationsCount} max={99} invisible={unreadNotificationsCount === 0}>
              {t_i18n('Alerts')}
            </Badge>
          )}
        />
        <Tab
          value="news-feed"
          sx={{ textTransform: 'none' }}
          label={(
            <Badge color="error" badgeContent={unreadNewsFeedsCount} max={99} invisible={unreadNewsFeedsCount === 0}>
              {t_i18n('XTM Hub News Feed')}
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
