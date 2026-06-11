import { InsertChartOutlined, LibraryBooksOutlined, NotificationsOutlined } from '@mui/icons-material';
import type { ElementType } from 'react';

const NEWS_FEED_ICON_MAP: Record<string, ElementType> = {
  RESOURCE_CUSTOM_DASHBOARD: InsertChartOutlined,
  RESOURCE_PLAYBOOK: LibraryBooksOutlined,
};

const NEWS_FEED_LABEL_MAP: Record<string, string> = {
  RESOURCE_CUSTOM_DASHBOARD: 'New Custom Dashboard',
  RESOURCE_PLAYBOOK: 'New Playbook',
};

export const isKnownNewsFeedType = (type: string): boolean =>
  Object.prototype.hasOwnProperty.call(NEWS_FEED_ICON_MAP, type);

export const getNewsFeedIcon = (type: string): ElementType =>
  NEWS_FEED_ICON_MAP[type] ?? NotificationsOutlined;

export const getNewsFeedLabel = (type: string): string | undefined =>
  NEWS_FEED_LABEL_MAP[type];
