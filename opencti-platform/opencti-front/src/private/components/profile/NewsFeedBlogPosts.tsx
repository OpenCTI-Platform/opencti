import { OpenInNewOutlined } from '@mui/icons-material';
import React, { FunctionComponent, Suspense, useCallback, useEffect, useMemo } from 'react';
import { graphql, PreloadedQuery, useMutation, usePreloadedQuery, useSubscription } from 'react-relay';
import Button from '@common/button/Button';
import DataTableSearchEmptyState from '../../../components/dataGrid/components/DataTableSearchEmptyState';
import Loader, { LoaderVariant } from '../../../components/Loader';
import { useFormatter } from '../../../components/i18n';
import useAuth from '../../../utils/hooks/useAuth';
import { useQueryLoadingWithLoadQuery } from '../../../utils/hooks/useQueryLoading';
import { buildNewsFeedBlogSeeAllUrl, NEWS_FEED_BLOG_POST_TYPE } from '../../../utils/NewsFeed';
import NewsFeedBlogPostCard from './NewsFeedBlogPostCard';
import type { NewsFeedBlogPostsQuery, NewsFeedBlogPostsQuery$variables } from './__generated__/NewsFeedBlogPostsQuery.graphql';

// The Hub provisions the latest blog posts only, this is a safety net and not a pagination.
const MAX_BLOG_POSTS = 50;

const newsFeedBlogPostsQuery = graphql`
  query NewsFeedBlogPostsQuery(
    $count: Int!
    $orderBy: NewsFeedItemsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    myNewsFeeds(
      first: $count
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) {
      edges {
        node {
          id
          title
          tags
          metadata {
            key
            value
          }
          creation_date
        }
      }
    }
  }
`;

const newsFeedBlogPostsSubscription = graphql`
  subscription NewsFeedBlogPostsSubscription {
    newsFeedItem {
      id
    }
  }
`;

const newsFeedBlogPostsDeletedSubscription = graphql`
  subscription NewsFeedBlogPostsDeletedSubscription {
    newsFeedItemDeleted
  }
`;

const newsFeedBlogPostsMarkAllAsReadMutation = graphql`
  mutation NewsFeedBlogPostsMarkAllAsReadMutation {
    markAllNewsFeedItemsAsRead(category: BLOG_POST)
  }
`;

interface NewsFeedBlogPostsComponentProps {
  queryRef: PreloadedQuery<NewsFeedBlogPostsQuery>;
  onNewItem: () => void;
}

const NewsFeedBlogPostsComponent: FunctionComponent<NewsFeedBlogPostsComponentProps> = ({ queryRef, onNewItem }) => {
  const { t_i18n } = useFormatter();
  const { settings } = useAuth();
  const data = usePreloadedQuery<NewsFeedBlogPostsQuery>(newsFeedBlogPostsQuery, queryRef);

  const [commitMarkAllAsRead] = useMutation(newsFeedBlogPostsMarkAllAsReadMutation);
  useEffect(() => {
    commitMarkAllAsRead({ variables: {} });
  }, [commitMarkAllAsRead]);

  const subConfig = useMemo(() => ({
    subscription: newsFeedBlogPostsSubscription,
    variables: {},
    onNext: () => onNewItem(),
  }), [onNewItem]);
  useSubscription(subConfig);

  const deletedSubConfig = useMemo(() => ({
    subscription: newsFeedBlogPostsDeletedSubscription,
    variables: {},
    onNext: () => onNewItem(),
  }), [onNewItem]);
  useSubscription(deletedSubConfig);

  const blogPosts = (data.myNewsFeeds?.edges ?? []).flatMap((edge) => (edge?.node ? [edge.node] : []));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24, paddingBottom: 24 }}>
      {blogPosts.length === 0 ? (
        // same empty state as the news feed datatable
        <DataTableSearchEmptyState rawSearchTerm={undefined} />
      ) : (
        // 3 cards per row at most, fewer when the page is too narrow to keep the cards readable
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(max(320px, calc((100% - 48px) / 3)), 1fr))', gap: 24 }}>
          {blogPosts.map((blogPost) => (
            <NewsFeedBlogPostCard key={blogPost.id} item={blogPost} />
          ))}
        </div>
      )}
      <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
        <Button
          variant="secondary"
          component="a"
          href={buildNewsFeedBlogSeeAllUrl(settings.id, settings.platform_xtmhub_url)}
          target="_blank"
          rel="noopener noreferrer"
          endIcon={<OpenInNewOutlined fontSize="small" />}
        >
          {t_i18n('See all')}
        </Button>
      </div>
    </div>
  );
};

const NewsFeedBlogPosts: FunctionComponent = () => {
  const { me } = useAuth();

  const queryVariables = {
    count: MAX_BLOG_POSTS,
    orderBy: 'creation_date',
    orderMode: 'desc',
    filters: {
      mode: 'and',
      filters: [
        { key: 'entity_type', values: ['NewsFeedItem'], operator: 'eq', mode: 'or' },
        { key: 'user_id', values: [me.id], operator: 'eq', mode: 'or' },
        { key: 'news_feed_type', values: [NEWS_FEED_BLOG_POST_TYPE], operator: 'eq', mode: 'or' },
      ],
      filterGroups: [],
    },
  } as unknown as NewsFeedBlogPostsQuery$variables;

  const [queryRef, loadQuery] = useQueryLoadingWithLoadQuery<NewsFeedBlogPostsQuery>(
    newsFeedBlogPostsQuery,
    queryVariables,
  );

  const handleNewItem = useCallback(() => {
    loadQuery(queryVariables, { fetchPolicy: 'network-only' });
  }, [loadQuery, me.id]);

  return queryRef ? (
    <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <NewsFeedBlogPostsComponent queryRef={queryRef} onNewItem={handleNewItem} />
    </Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement} />
  );
};

export default NewsFeedBlogPosts;
