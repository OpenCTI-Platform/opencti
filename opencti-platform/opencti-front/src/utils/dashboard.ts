import { copyToClipboard } from './utils';
import { APP_BASE_PATH } from '../relay/environment';

// eslint-disable-next-line import/prefer-default-export
export const copyPublicLinkUrl = (t: (text: string) => string, uriKey: string) => {
  copyToClipboard(
    t,
    `${window.location.origin}${APP_BASE_PATH}/public/dashboard/${uriKey.toLowerCase()}`,
  );
};
