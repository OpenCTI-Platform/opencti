import { copyToClipboard } from '../../../../../utils/utils';
import { APP_BASE_PATH } from '../../../../../relay/environment';

export const copyPublicDashboardLinkUrl = (t: (text: string) => string, uriKey: string) => {
  copyToClipboard(
    t,
    `${window.location.origin}${APP_BASE_PATH}/public/dashboard/${uriKey.toLowerCase()}`,
  );
};
