import { ArticleOutlined, InsertChartOutlined, InsightsOutlined, IntegrationInstructionsOutlined, LibraryBooksOutlined, NotificationsOutlined } from '@mui/icons-material';
import type { ElementType } from 'react';

interface NewsFeedTypeDefinition {
  icon: ElementType;
  label: string;
}

export const NEWS_FEED_BLOG_POST_TYPE = 'BLOG_POST';

const NEWS_FEED_TYPE_MAP: Record<string, NewsFeedTypeDefinition> = {
  RESOURCE_CUSTOM_DASHBOARD: { icon: InsertChartOutlined, label: 'New Custom Dashboard' },
  RESOURCE_PLAYBOOK: { icon: LibraryBooksOutlined, label: 'New Playbook' },
  RESOURCE_CUSTOM_VIEW: { icon: InsightsOutlined, label: 'New Custom View' },
  RESOURCE_INTEGRATION: { icon: IntegrationInstructionsOutlined, label: 'New Integration' },
  [NEWS_FEED_BLOG_POST_TYPE]: { icon: ArticleOutlined, label: 'Blogpost' },
};

export const isKnownNewsFeedType = (type: string): boolean =>
  Object.prototype.hasOwnProperty.call(NEWS_FEED_TYPE_MAP, type);

export const getNewsFeedIcon = (type: string): ElementType =>
  NEWS_FEED_TYPE_MAP[type]?.icon ?? NotificationsOutlined;

export const getNewsFeedLabel = (type: string): string | undefined =>
  NEWS_FEED_TYPE_MAP[type]?.label;

type NewsFeedMetadata = readonly ({ readonly key: string; readonly value: string | null | undefined } | null | undefined)[] | null | undefined;

export const getNewsFeedMetadataValue = (metadata: NewsFeedMetadata, key: string): string | undefined => {
  const value = metadata?.find((m) => m?.key === key)?.value;
  return value ? value : undefined;
};

/**
 * `author_names` is a JSON array of names serialized as a string by the Hub.
 * Anything that is not a JSON array (invalid JSON, an object, a string...) gives no author.
 */
export const parseNewsFeedAuthorNames = (rawAuthorNames?: string | null): string[] => {
  if (!rawAuthorNames) return [];
  try {
    const parsed: unknown = JSON.parse(rawAuthorNames);
    if (!Array.isArray(parsed)) return [];
    return parsed
      .filter((name): name is string => typeof name === 'string')
      .map((name) => name.trim())
      .filter((name) => name.length > 0);
  } catch (_) {
    return [];
  }
};

/** `read_minutes` is serialized as a string by the Hub, only a positive integer is displayed. */
export const parseNewsFeedReadMinutes = (rawReadMinutes?: string | null): number | undefined => {
  if (!rawReadMinutes || !/^\d+$/.test(rawReadMinutes.trim())) return undefined;
  const minutes = Number(rawReadMinutes);
  return minutes > 0 ? minutes : undefined;
};

const FILIGRAN_BLOG_URL = 'https://filigran.io/blog';
const FILIGRAN_STAGING_BLOG_URL = 'https://staging.filigran.io/blog';

/**
 * Link of the "See all" button of the blog posts: the Filigran blog (staging blog when the platform is
 * linked to a staging XTM Hub), tagged with the UTM of the news feed. No `platform_id`: this link
 * does not go through the Hub redirect, so it has no redirect telemetry.
 */
export const buildNewsFeedBlogSeeAllUrl = (platformId?: string | null, xtmHubUrl?: string | null): string => {
  let isStaging = false;
  try {
    isStaging = !!xtmHubUrl && /(^|\.)staging\./.test(new URL(xtmHubUrl).hostname);
  } catch (_) {
    // malformed hub url, fallback on the production blog
  }
  const url = new URL(isStaging ? FILIGRAN_STAGING_BLOG_URL : FILIGRAN_BLOG_URL);
  if (platformId) url.searchParams.append('utm_source', platformId);
  url.searchParams.append('utm_medium', 'newsfeed');
  url.searchParams.append('utm_campaign', 'blog_posts');
  url.searchParams.append('utm_content', 'see_all');
  return url.toString();
};
