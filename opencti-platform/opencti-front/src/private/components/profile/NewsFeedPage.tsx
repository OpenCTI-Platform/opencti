import { Badge } from '@mui/material';
import Tab from '@mui/material/Tab';
import Tabs from '@mui/material/Tabs';
import React, { FunctionComponent, useEffect, useMemo, useState } from 'react';
import { graphql, useLazyLoadQuery, useSubscription } from 'react-relay';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { useFormatter } from '../../../components/i18n';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import useAuth from '../../../utils/hooks/useAuth';
import { NewsFeedPageNewsFeedNumberSubscription$data } from './__generated__/NewsFeedPageNewsFeedNumberSubscription.graphql';
import { NewsFeedPageNotificationNumberSubscription$data } from './__generated__/NewsFeedPageNotificationNumberSubscription.graphql';
import type { NewsFeedPageQuery } from './__generated__/NewsFeedPageQuery.graphql';
import NewsFeed from './NewsFeed';

const newsFeedPageQuery = graphql`
  query NewsFeedPageQuery {
    myUnreadNotificationsCount
    myUnreadNewsFeedsCount
  }
`;

const notificationsNumberSubscription = graphql`
  subscription NewsFeedPageNotificationNumberSubscription {
    notificationsNumber {
      count
    }
  }
`;

const newsFeedNumberSubscription = graphql`
  subscription NewsFeedPageNewsFeedNumberSubscription {
    newsFeedsNumber {
      count
    }
  }
`;

const NewsFeedSettings: FunctionComponent = () => null;

const NewsFeedPage: FunctionComponent = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  const { settings, me } = useAuth();
  const isXTMHubRegistered = settings.xtm_hub_registration_status === 'registered';

  setTitle(t_i18n('News Feed'));

  const data = useLazyLoadQuery<NewsFeedPageQuery>(newsFeedPageQuery, {});
  const [activeTab, setActiveTab] = useState<'feed' | 'settings'>('feed');
  const [liveNotificationsCount, setLiveNotificationsCount] = useState<number | null>(null);
  const [liveNewsFeedsCount, setLiveNewsFeedsCount] = useState<number | null>(null);

  const notificationsSubConfig = useMemo(() => ({
    subscription: notificationsNumberSubscription,
    variables: {},
    onNext: (response: NewsFeedPageNotificationNumberSubscription$data | null | undefined | unknown) => {
      const count = response ? (response as NewsFeedPageNotificationNumberSubscription$data).notificationsNumber?.count : null;
      setLiveNotificationsCount(count ?? null);
    },
  }), []);
  useSubscription(notificationsSubConfig);

  const newsFeedSubConfig = useMemo(() => ({
    subscription: newsFeedNumberSubscription,
    variables: {},
    onNext: (response: NewsFeedPageNewsFeedNumberSubscription$data | null | undefined | unknown) => {
      const count = response ? (response as NewsFeedPageNewsFeedNumberSubscription$data).newsFeedsNumber?.count : null;
      setLiveNewsFeedsCount(count ?? null);
    },
  }), []);
  useSubscription(newsFeedSubConfig);

  const unreadNotificationsCount = liveNotificationsCount !== null
    ? liveNotificationsCount
    : (data.myUnreadNotificationsCount ?? 0);
  const isUnsubscribedFromAllNewsFeeds = me.unsubscribed_news_feed_types?.includes('*') ?? false;
  const unreadNewsFeedsCount = isXTMHubRegistered && !isUnsubscribedFromAllNewsFeeds && liveNewsFeedsCount !== null
    ? liveNewsFeedsCount
    : (isXTMHubRegistered && !isUnsubscribedFromAllNewsFeeds ? (data.myUnreadNewsFeedsCount ?? 0) : 0);

  return (
    <div>
      <Breadcrumbs elements={[{ label: t_i18n('News Feed'), current: true }]} />
      <Tabs value={activeTab} onChange={(_, value) => setActiveTab(value)}>
        <Tab
          value="feed"
          sx={{ textTransform: 'none' }}
          label={(
            <Badge color="error" badgeContent={unreadNewsFeedsCount} max={99} invisible={unreadNewsFeedsCount === 0}>
              {t_i18n('Feed')}
            </Badge>
          )}
        />
        <Tab
          value="settings"
          sx={{ textTransform: 'none' }}
          label={(
            <Badge color="error" badgeContent={unreadNotificationsCount} max={99} invisible={unreadNotificationsCount === 0}>
              {t_i18n('Settings')}
            </Badge>
          )}
        />
      </Tabs>
      <div style={{ marginTop: 20 }}>
        {activeTab === 'feed' ? <NewsFeed /> : <NewsFeedSettings />}
      </div>
    </div>
  );
};

export default NewsFeedPage;
