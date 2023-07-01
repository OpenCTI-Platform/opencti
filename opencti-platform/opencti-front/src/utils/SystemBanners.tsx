import * as R from 'ramda';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { RecordSourceProxy } from 'relay-runtime';
import { commitLocalUpdate } from '../relay/environment';
import { SystemBannersQuery } from './__generated__/SystemBannersQuery.graphql';

const settingsQuery = graphql`
  query SystemBannersQuery {
    settings {
      platform_banner_text
      platform_banner_level
    }
  }
`;

/** Height in pixels for the top and bottom system banners */
export const SYSTEM_BANNER_HEIGHT = 20;

export const classificationLevels = ['GREEN', 'RED', 'YELLOW'];

interface BannerSettings {
  bannerLevel?: string | null;
  bannerText?: string | null;
  bannerHeight: string;
}

export function validateBannerLevel(bannerLevel?: string | null) {
  return (bannerLevel
    && classificationLevels.find((level) => level === bannerLevel)) || null;
}

type SettingsOptions = {
  platform_banner_level: string;
  platform_banner_text: string;
};

export function useBannerSettings(settingsOptions: SettingsOptions | null = null): BannerSettings {
  const settings = settingsOptions || useLazyLoadQuery<SystemBannersQuery>(settingsQuery, {})?.settings;
  const bannerLevel = settings && validateBannerLevel(settings.platform_banner_level);
  const bannerText = (bannerLevel && settings && settings.platform_banner_text) || null;
  const bannerHeight = bannerLevel ? `${SYSTEM_BANNER_HEIGHT}px` : '0';
  return { bannerText, bannerLevel, bannerHeight };
}

export function getBannerSettings(callback: (bannerSettings: BannerSettings) => void) {
  commitLocalUpdate((store: RecordSourceProxy) => {
    const settings = store.getRoot().getLinkedRecord('settings');

    const bannerLevel = settings && validateBannerLevel(
      settings.getValue('platform_banner_level') as string,
    );
    const bannerText = (bannerLevel && settings
      && settings.getValue('platform_banner_text')) as string
      || null;
    const bannerHeight = bannerLevel ? `${SYSTEM_BANNER_HEIGHT}px` : '0';

    if (R.is(Function, callback)) {
      callback({ bannerText, bannerLevel, bannerHeight });
    }
  });
}

export function bannerColorClassName(color: string, prefix = 'banner') {
  if (!R.is(String, color)) return '';
  let colorName = color.toLowerCase();
  colorName = colorName.substring(0, 1).toUpperCase() + colorName.substring(1);
  return `${prefix}${colorName}`;
}
