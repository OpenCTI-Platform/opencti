import { InsertChartOutlined, LibraryBooksOutlined, NotificationsOutlined } from '@mui/icons-material';
import type { ElementType } from 'react';

// News feed item types known by this OpenCTI version. The list grows over time; an item whose type
// is not listed here was introduced by a newer XTM Hub and cannot be displayed properly yet.
const NEWS_FEED_ICON_MAP: Record<string, ElementType> = {
  RESOURCE_CUSTOM_DASHBOARD: InsertChartOutlined,
  RESOURCE_PLAYBOOK: LibraryBooksOutlined,
};

export const isKnownNewsFeedType = (type: string): boolean => Object.prototype.hasOwnProperty.call(NEWS_FEED_ICON_MAP, type);

export const getNewsFeedIcon = (type: string): ElementType => NEWS_FEED_ICON_MAP[type] ?? NotificationsOutlined;
