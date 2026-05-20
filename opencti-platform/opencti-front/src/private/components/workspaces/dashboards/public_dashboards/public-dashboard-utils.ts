import { v4 as uuidv4 } from 'uuid';
import { copyToClipboard } from '../../../../../utils/utils';
import { APP_BASE_PATH } from '../../../../../relay/environment';

/**
 * Generates a URI key slug from a dashboard name.
 * Strips non-ASCII characters and replaces spaces with hyphens.
 * Falls back to a UUID v4 if the resulting slug is empty (e.g. fully non-Latin name).
 */
export const generatePublicDashboardUriKey = (name: string): string => {
  const slug = name.replace(/[^a-zA-Z0-9\s-]+/g, '').replace(/\s+/g, '-').toLowerCase();
  return slug || uuidv4();
};

export const copyPublicDashboardLinkUrl = (t: (text: string) => string, uriKey: string) => {
  copyToClipboard(
    t,
    `${window.location.origin}${APP_BASE_PATH}/public/dashboard/${uriKey.toLowerCase()}`,
  );
};
