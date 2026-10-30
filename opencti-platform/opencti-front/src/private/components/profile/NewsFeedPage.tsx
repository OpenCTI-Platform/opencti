import Card from '@common/card/Card';
import { Tabs, TabsList, TabsTrigger, Text } from '@filigran/design-system';
import { Stack } from '@mui/material';
import SettingsOutlinedIcon from '@mui/icons-material/SettingsOutlined';
import React, { FunctionComponent, useCallback, useEffect, useState } from 'react';
import { graphql, useFragment, useLazyLoadQuery } from 'react-relay';
import Breadcrumbs from 'src/components/Breadcrumbs';
import { useFormatter } from 'src/components/i18n';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import useAuth from '../../../utils/hooks/useAuth';
import { commitMutation, requestSubscription } from 'src/relay/environment';
import { NewsFeedPageNewsFeedNumberSubscription$data } from './__generated__/NewsFeedPageNewsFeedNumberSubscription.graphql';
import { NewsFeedPageSettings_settings$key } from './__generated__/NewsFeedPageSettings_settings.graphql';
import { NewsFeedPageFieldPatchMutation$variables } from './__generated__/NewsFeedPageFieldPatchMutation.graphql';
import type { NewsFeedPageQuery } from './__generated__/NewsFeedPageQuery.graphql';
import NewsFeed from './NewsFeed';
import NewsFeedSettings from './NewsFeedSettings';
import XtmHubDisconnectedBanner from '../xtm_hub/XtmHubDisconnectedBanner';
import { CampaignOutlined } from '@mui/icons-material';

const newsFeedPageFieldPatch = graphql`
  mutation NewsFeedPageFieldPatchMutation(
    $input: [EditInput]!
    $password: String
  ) {
    meEdit(input: $input, password: $password) {
      id
      unsubscribed_news_feed_types
    }
  }
`;

const newsFeedPageSettingsFragment = graphql`
  fragment NewsFeedPageSettings_settings on Settings {
    xtm_hub_available_news_feed_types
  }
`;

const newsFeedPageQuery = graphql`
  query NewsFeedPageQuery {
    myUnreadNewsFeedsCount
    settings {
      ...NewsFeedPageSettings_settings
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

const NewsFeedPage: FunctionComponent = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  const { settings, me } = useAuth();
  const isXTMHubRegistered = settings.xtm_hub_registration_status === 'registered';
  const isXTMHubUnreachable = settings.xtm_hub_backend_is_reachable === false;

  setTitle(t_i18n('News Feed'));

  const data = useLazyLoadQuery<NewsFeedPageQuery>(newsFeedPageQuery, {});
  const [activeTab, setActiveTab] = useState<'news-feed' | 'settings'>('news-feed');
  const [liveNewsFeedsCount, setLiveNewsFeedsCount] = useState<number | null>(null);

  const isUnsubscribedFromAllNewsFeeds = me.unsubscribed_news_feed_types?.includes('*') ?? false;
  const handleNewNewsFeedNumber = useCallback((
    response: NewsFeedPageNewsFeedNumberSubscription$data | null | undefined | unknown,
  ) => {
    const count = response ? (response as NewsFeedPageNewsFeedNumberSubscription$data).newsFeedsNumber?.count : null;
    setLiveNewsFeedsCount(count ?? null);
  }, [setLiveNewsFeedsCount]);

  const shouldSubscribeToNewsFeed = isXTMHubRegistered && !isUnsubscribedFromAllNewsFeeds;
  useEffect(() => {
    if (!shouldSubscribeToNewsFeed) return undefined;
    const sub = requestSubscription({
      subscription: newsFeedNumberSubscription,
      variables: {},
      onNext: handleNewNewsFeedNumber,
    });
    return () => sub.dispose();
  }, [shouldSubscribeToNewsFeed, handleNewNewsFeedNumber]);

  const unreadNewsFeedsCount = shouldSubscribeToNewsFeed && liveNewsFeedsCount !== null
    ? liveNewsFeedsCount
    : (shouldSubscribeToNewsFeed ? (data.myUnreadNewsFeedsCount ?? 0) : 0);

  const handleSubmitField = (name: string, value: string[]) => {
    const variables: NewsFeedPageFieldPatchMutation$variables = {
      input: [{ key: name, value }],
    };
    commitMutation({
      mutation: newsFeedPageFieldPatch,
      variables,
      updater: undefined,
      optimisticUpdater: undefined,
      optimisticResponse: undefined,
      onCompleted: () => {},
      onError: () => {},
      setSubmitting: undefined,
    });
  };

  const settingsFragmentData = useFragment<NewsFeedPageSettings_settings$key>(
    newsFeedPageSettingsFragment,
    data.settings,
  );

  return (
    <div>
      <Breadcrumbs elements={[{ label: t_i18n('XTM Hub News Feed'), current: true }]} />
      <Text variant="title-xl" className="mt-6 mb-6">
        {t_i18n('XTM Hub News Feed')}
      </Text>
      {isXTMHubUnreachable ? (
        <div style={{ marginBottom: 20 }}>
          <XtmHubDisconnectedBanner unreachable />
        </div>
      ) : !isXTMHubRegistered && (
        <div style={{ marginBottom: 20 }}>
          <XtmHubDisconnectedBanner />
        </div>
      )}
      <Tabs value={activeTab} onValueChange={(value) => setActiveTab(value as 'news-feed' | 'settings')} panels="external">
        <TabsList>
          <TabsTrigger
            value="news-feed"
            icon={<CampaignOutlined fontSize="small" />}
            badge={unreadNewsFeedsCount}
            badgeMax={99}
            badgeColor="error"
            badgeInvisible={unreadNewsFeedsCount === 0}
          >
            {t_i18n('News feed')}
          </TabsTrigger>
          <TabsTrigger
            value="settings"
            icon={<SettingsOutlinedIcon fontSize="small" />}
          >
            {t_i18n('Settings')}
          </TabsTrigger>
        </TabsList>
      </Tabs>
      <div style={{ marginTop: 20 }}>
        {activeTab === 'news-feed' ? (
          <NewsFeed />
        ) : (
          <Stack spacing={3} sx={{ width: '50%' }}>
            <Card title={t_i18n('XTM Hub News Feed settings')}>
              <NewsFeedSettings
                availableNewsFeedTypes={[...(settingsFragmentData.xtm_hub_available_news_feed_types ?? [])]}
                unsubscribedNewsFeedTypes={me.unsubscribed_news_feed_types ? [...me.unsubscribed_news_feed_types] : []}
                onSubmitField={handleSubmitField}
              />
            </Card>
          </Stack>
        )}
      </div>
    </div>
  );
};

export default NewsFeedPage;
