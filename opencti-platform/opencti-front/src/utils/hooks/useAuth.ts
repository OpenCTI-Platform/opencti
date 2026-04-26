import React, { useContext } from 'react';
import { PrivateRootPreloadedQuery$data } from '../../private/__generated__/PrivateRootPreloadedQuery.graphql';
import { RootSettings$data } from '../../private/__generated__/RootSettings.graphql';
import { RootMe_data$data } from '../../private/__generated__/RootMe_data.graphql';

export interface BannerSettings {
  bannerLevel?: string | null;
  bannerText?: string | null;
  idleLimit: number;
  sessionLimit: number;
  bannerHeight: string;
  bannerHeightNumber: number;
}

export type PlatformLang
  = | 'de-de'
    | 'en-us'
    | 'es-es'
    | 'fr-fr'
    | 'it-it'
    | 'ja-jp'
    | 'ko-kr'
    | 'zh-cn'
    | 'ru-ru';

const defaultLang: PlatformLang = 'en-us';

export interface UserContextType {
  me: RootMe_data$data | undefined;
  settings: RootSettings$data | undefined;
  bannerSettings: BannerSettings | undefined;
  entitySettings: PrivateRootPreloadedQuery$data['entitySettings'] | undefined;
  isXTMHubAccessible: boolean | null | undefined;
  about: PrivateRootPreloadedQuery$data['about'] | undefined;
  themes: PrivateRootPreloadedQuery$data['themes'] | undefined;
  unitSystem: string;
  locale: PlatformLang;
  tz: string;
}

const defaultContext = {
  me: undefined,
  settings: undefined,
  bannerSettings: undefined,
  entitySettings: undefined,
  schema: undefined,
  isXTMHubAccessible: undefined,
  about: undefined,
  themes: undefined,
  locale: defaultLang,
  unitSystem: 'Metric',
  tz: 'UTC',
};
export const UserContext = React.createContext<UserContextType>(defaultContext);

const useAuth = () => {
  const {
    me,
    settings,
    bannerSettings,
    entitySettings,
    isXTMHubAccessible,
    about,
    themes,
    unitSystem,
    locale,
    tz,
  } = useContext(UserContext);
  if (!me || !settings || !bannerSettings || !entitySettings || !about || !themes) {
    throw new Error('Invalid user context !');
  }
  return {
    me,
    settings,
    bannerSettings,
    entitySettings,
    isXTMHubAccessible,
    about,
    themes,
    locale,
    tz,
    unitSystem,
  };
};

export default useAuth;
