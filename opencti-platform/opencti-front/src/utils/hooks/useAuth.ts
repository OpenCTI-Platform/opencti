import React, { useContext } from 'react';
import { RootPrivateQuery$data } from '../../private/__generated__/RootPrivateQuery.graphql';
import { ModuleHelper } from '../platformModulesHelper';
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

export type FilterDefinition = {
  filterKey: string;
  label: string;
  type: string; // boolean, date, integer, float, id, string, text, or object
  multiple: boolean;
  subEntityTypes: string[];
  elementsForFilterValuesSearch: string[]; // not empty if type = 'id', type = 'enum' or type = 'vocabulary'
  subFilters?: FilterDefinition[] | null;
};

export type SchemaType = {
  scos: { id: string; label: string }[];
  sdos: { id: string; label: string }[];
  smos: { id: string; label: string }[];
  scrs: { id: string; label: string }[];
  schemaRelationsTypesMapping: Map<string, readonly string[]>;
  schemaRelationsRefTypesMapping: Map<string, readonly { readonly name: string; readonly toTypes: readonly string[] }[]>;
  filterKeysSchema: Map<string, Map<string, FilterDefinition>>;
};

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
  entitySettings: RootPrivateQuery$data['entitySettings'] | undefined;
  platformModuleHelpers: ModuleHelper | undefined;
  schema: SchemaType | undefined;
  isXTMHubAccessible: boolean | null | undefined;
  about: RootPrivateQuery$data['about'] | undefined;
  themes: RootPrivateQuery$data['themes'] | undefined;
  unitSystem: string;
  locale: PlatformLang;
  tz: string;
}

const defaultContext = {
  me: undefined,
  settings: undefined,
  bannerSettings: undefined,
  entitySettings: undefined,
  platformModuleHelpers: undefined,
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
    platformModuleHelpers,
    schema,
    isXTMHubAccessible,
    about,
    themes,
    unitSystem,
    locale,
    tz,
  } = useContext(UserContext);
  if (!me || !settings || !bannerSettings || !entitySettings || !platformModuleHelpers || !schema || !about || !themes) {
    throw new Error('Invalid user context !');
  }
  return { me, settings, bannerSettings, entitySettings,
    platformModuleHelpers, schema, isXTMHubAccessible,
    about, themes, locale, tz, unitSystem };
};

export default useAuth;
