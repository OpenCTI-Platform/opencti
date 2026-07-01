import { DashboardCustomizeOutlined, InsertChartOutlined, LibraryBooksOutlined, NotificationsOutlined } from '@mui/icons-material';
import type { ElementType } from 'react';

interface NewsFeedTypeDefinition {
  icon: ElementType;
  label: string;
}

const NEWS_FEED_TYPE_MAP: Record<string, NewsFeedTypeDefinition> = {
  RESOURCE_CUSTOM_DASHBOARD: { icon: InsertChartOutlined, label: 'New Custom Dashboard' },
  RESOURCE_PLAYBOOK: { icon: LibraryBooksOutlined, label: 'New Playbook' },
  RESOURCE_CUSTOM_VIEW: { icon: DashboardCustomizeOutlined, label: 'New Custom View' },
};

export const isKnownNewsFeedType = (type: string): boolean =>
  Object.prototype.hasOwnProperty.call(NEWS_FEED_TYPE_MAP, type);

export const getNewsFeedIcon = (type: string): ElementType =>
  NEWS_FEED_TYPE_MAP[type]?.icon ?? NotificationsOutlined;

export const getNewsFeedLabel = (type: string): string | undefined =>
  NEWS_FEED_TYPE_MAP[type]?.label;
