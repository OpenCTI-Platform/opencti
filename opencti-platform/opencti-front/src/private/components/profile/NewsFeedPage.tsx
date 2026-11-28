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
import NewsFeedGitHubReleases from './NewsFeedGitHubReleases';
import NewsFeedSettings from './NewsFeedSettings';
import XtmHubDisconnectedBanner from '../xtm_hub/XtmHubDisconnectedBanner';
import { ArticleOutlined, CampaignOutlined, SensorsOutlined } from '@mui/icons-material';
import NewsFeedBlogPosts from './NewsFeedBlogPosts';
import { NEWS_FEED_BLOG_POST_TYPE, NEWS_FEED_GITHUB_RELEASE_TYPE } from '../../../utils/NewsFeed';

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
    myUnreadNewsFeedsCounts {
      resource_count
      blog_post_count
      github_release_count
    }
    settings {
      ...NewsFeedPageSettings_settings
    }
  }
`;

const newsFeedNumberSubscription = graphql`
  subscription NewsFeedPageNewsFeedNumberSubscription {
    newsFeedsNumber {
      resource_count
      blog_post_count
      github_release_count
    }
  }
`;

type NewsFeedTab = 'news-feed' | 'blog-posts' | 'last-releases' | 'settings';

interface LiveCounts {
  resources: number | null;
  blogPosts: number | null;
  gitHubReleases: number | null;
}

const EMPTY_LIVE_COUNTS: LiveCounts = { resources: null, blogPosts: null, gitHubReleases: null };

const NewsFeedPage: FunctionComponent = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  const { settings, me } = useAuth();
  const isXTMHubRegistered = settings.xtm_hub_registration_status === 'registered';
  const isXTMHubUnreachable = settings.xtm_hub_backend_is_reachable === false;

  setTitle(t_i18n('News Feed'));

  const data = useLazyLoadQuery<NewsFeedPageQuery>(newsFeedPageQuery, {});
  const [activeTab, setActiveTab] = useState<NewsFeedTab>('news-feed');
  const [liveCounts, setLiveCounts] = useState<LiveCounts>(EMPTY_LIVE_COUNTS);

  const isUnsubscribedFromAllNewsFeeds = me.unsubscribed_news_feed_types?.includes('*') ?? false;
  const handleNewNewsFeedNumber = useCallback((
    response: NewsFeedPageNewsFeedNumberSubscription$data | null | undefined | unknown,
  ) => {
    const newsFeedsNumber = response ? (response as NewsFeedPageNewsFeedNumberSubscription$data).newsFeedsNumber : null;
    setLiveCounts({
      resources: newsFeedsNumber?.resource_count ?? null,
      blogPosts: newsFeedsNumber?.blog_post_count ?? null,
      gitHubReleases: newsFeedsNumber?.github_release_count ?? null,
    });
  }, [setLiveCounts]);

  const shouldSubscribeToNewsFeed = isXTMHubRegistered && !isUnsubscribedFromAllNewsFeeds;
  useEffect(() => {
    if (!shouldSubscribeToNewsFeed) {
      // the last live counts would be stale, and win over the query, once the feed is enabled again
      setLiveCounts(EMPTY_LIVE_COUNTS);
      return undefined;
    }
    const sub = requestSubscription({
      subscription: newsFeedNumberSubscription,
      variables: {},
      onNext: handleNewNewsFeedNumber,
    });
    return () => sub.dispose();
  }, [shouldSubscribeToNewsFeed, handleNewNewsFeedNumber]);

  // Resources, blogposts and GitHub releases are counted, and read, independently: each tab shows its own unread count.
  const queryCounts = data.myUnreadNewsFeedsCounts;
  const unreadResourcesCount = shouldSubscribeToNewsFeed ? (liveCounts.resources ?? queryCounts?.resource_count ?? 0) : 0;
  const unreadBlogPostsCount = shouldSubscribeToNewsFeed ? (liveCounts.blogPosts ?? queryCounts?.blog_post_count ?? 0) : 0;
  const unreadGitHubReleasesCount = shouldSubscribeToNewsFeed ? (liveCounts.gitHubReleases ?? queryCounts?.github_release_count ?? 0) : 0;

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
  const availableNewsFeedTypes = settingsFragmentData.xtm_hub_available_news_feed_types ?? [];

  // The blogposts tab only exists when the XTM Hub provisions blogposts for this platform version.
  const isBlogPostAvailable = availableNewsFeedTypes.includes(NEWS_FEED_BLOG_POST_TYPE);
  const isLastReleasesAvailable = availableNewsFeedTypes.includes(NEWS_FEED_GITHUB_RELEASE_TYPE);
  const isActiveTabUnavailable = (activeTab === 'blog-posts' && !isBlogPostAvailable)
    || (activeTab === 'last-releases' && !isLastReleasesAvailable);
  const displayedTab = isActiveTabUnavailable ? 'news-feed' : activeTab;

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
      <Tabs value={displayedTab} onValueChange={(value) => setActiveTab(value as NewsFeedTab)} panels="external">
        <TabsList>
          <TabsTrigger
            value="news-feed"
            icon={<CampaignOutlined fontSize="small" />}
            badge={unreadResourcesCount}
            badgeMax={99}
            badgeColor="error"
            badgeInvisible={unreadResourcesCount === 0}
          >
            {t_i18n('News feed')}
          </TabsTrigger>
          {isBlogPostAvailable && (
            <TabsTrigger
              value="blog-posts"
              icon={<ArticleOutlined fontSize="small" />}
              badge={unreadBlogPostsCount}
              badgeMax={99}
              badgeColor="error"
              badgeInvisible={unreadBlogPostsCount === 0}
            >
              {t_i18n('Blogpost')}
            </TabsTrigger>
          )}
          {isLastReleasesAvailable && (
            <TabsTrigger
              value="last-releases"
              icon={<SensorsOutlined fontSize="small" />}
              badge={unreadGitHubReleasesCount}
              badgeMax={99}
              badgeColor="error"
              badgeInvisible={unreadGitHubReleasesCount === 0}
            >
              {t_i18n('Last releases')}
            </TabsTrigger>
          )}
          <TabsTrigger
            value="settings"
            icon={<SettingsOutlinedIcon fontSize="small" />}
          >
            {t_i18n('Settings')}
          </TabsTrigger>
        </TabsList>
      </Tabs>
      <div style={{ marginTop: 20 }}>
        {displayedTab === 'news-feed' && (
          <NewsFeed markBlogPostsAsRead={!isBlogPostAvailable} markGitHubReleasesAsRead={!isLastReleasesAvailable} />
        )}
        {displayedTab === 'blog-posts' && <NewsFeedBlogPosts />}
        {displayedTab === 'last-releases' && <NewsFeedGitHubReleases />}
        {displayedTab === 'settings' && (
          <Stack spacing={3} sx={{ width: '50%' }}>
            <Card title={t_i18n('XTM Hub News Feed settings')}>
              <NewsFeedSettings
                availableNewsFeedTypes={[...availableNewsFeedTypes]}
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
