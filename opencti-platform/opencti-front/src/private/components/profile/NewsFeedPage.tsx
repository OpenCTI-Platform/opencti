import Card from '@common/card/Card';
import { Badge, Stack } from '@mui/material';
import Typography from '@mui/material/Typography';
import DynamicFeedOutlinedIcon from '@mui/icons-material/DynamicFeedOutlined';
import SettingsOutlinedIcon from '@mui/icons-material/SettingsOutlined';
import Tab from '@mui/material/Tab';
import Tabs from '@mui/material/Tabs';
import React, { FunctionComponent, useMemo, useState } from 'react';
import { graphql, useFragment, useLazyLoadQuery, useSubscription } from 'react-relay';
import Breadcrumbs from 'src/components/Breadcrumbs';
import { useFormatter } from 'src/components/i18n';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import useAuth from '../../../utils/hooks/useAuth';
import { commitMutation } from 'src/relay/environment';
import { NewsFeedPageNewsFeedNumberSubscription$data } from './__generated__/NewsFeedPageNewsFeedNumberSubscription.graphql';
import { NewsFeedPageSettings_settings$key } from './__generated__/NewsFeedPageSettings_settings.graphql';
import { NewsFeedPageFieldPatchMutation$variables } from './__generated__/NewsFeedPageFieldPatchMutation.graphql';
import type { NewsFeedPageQuery } from './__generated__/NewsFeedPageQuery.graphql';
import NewsFeed from './NewsFeed';
import NewsFeedSettings from './NewsFeedSettings';

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
    myUnreadNotificationsCount
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

  setTitle(t_i18n('News Feed'));

  const data = useLazyLoadQuery<NewsFeedPageQuery>(newsFeedPageQuery, {});
  const [activeTab, setActiveTab] = useState<'news-feed' | 'settings'>('news-feed');
  const [liveNewsFeedsCount, setLiveNewsFeedsCount] = useState<number | null>(null);

  const newsFeedSubConfig = useMemo(() => ({
    subscription: newsFeedNumberSubscription,
    variables: {},
    onNext: (response: NewsFeedPageNewsFeedNumberSubscription$data | null | undefined | unknown) => {
      const count = response ? (response as NewsFeedPageNewsFeedNumberSubscription$data).newsFeedsNumber?.count : null;
      setLiveNewsFeedsCount(count ?? null);
    },
  }), []);
  useSubscription(newsFeedSubConfig);

  const isUnsubscribedFromAllNewsFeeds = me.unsubscribed_news_feed_types?.includes('*') ?? false;
  const unreadNewsFeedsCount = isXTMHubRegistered && !isUnsubscribedFromAllNewsFeeds && liveNewsFeedsCount !== null
    ? liveNewsFeedsCount
    : (isXTMHubRegistered && !isUnsubscribedFromAllNewsFeeds ? (data.myUnreadNewsFeedsCount ?? 0) : 0);

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
      <Breadcrumbs elements={[{ label: t_i18n('XTM Hub news feed'), current: true }]} />
      <Typography variant="h2" sx={{ mt: 3, mb: 3 }}>
        {t_i18n('XTM Hub News Feed')}
      </Typography>
      <Tabs value={activeTab} onChange={(_, value) => setActiveTab(value)}>
        <Tab
          value="news-feed"
          sx={{ textTransform: 'none' }}
          label={(
            <Badge color="error" badgeContent={unreadNewsFeedsCount} max={99} invisible={unreadNewsFeedsCount === 0}>
              <Stack direction="row" alignItems="center" spacing={1}>
                <DynamicFeedOutlinedIcon fontSize="small" />
                <span>{t_i18n('News feed')}</span>
              </Stack>
            </Badge>
          )}
        />
        <Tab
          value="settings"
          sx={{ textTransform: 'none' }}
          label={(
            <Stack direction="row" alignItems="center" spacing={1}>
              <SettingsOutlinedIcon fontSize="small" />
              <span>{t_i18n('Settings')}</span>
            </Stack>
          )}
        />
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
