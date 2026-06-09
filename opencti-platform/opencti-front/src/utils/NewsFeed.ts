import {
  InsertChartOutlined,
  LibraryBooksOutlined,
  NotificationsOutlined,
} from "@mui/icons-material";
import type { ElementType } from "react";

const NEWS_FEED_ICON_MAP: Record<string, ElementType> = {
  RESOURCE_CUSTOM_DASHBOARD: InsertChartOutlined,
  RESOURCE_PLAYBOOK: LibraryBooksOutlined,
};

export const isKnownNewsFeedType = (type: string): boolean =>
  Object.prototype.hasOwnProperty.call(NEWS_FEED_ICON_MAP, type);

export const getNewsFeedIcon = (type: string): ElementType =>
  NEWS_FEED_ICON_MAP[type] ?? NotificationsOutlined;
