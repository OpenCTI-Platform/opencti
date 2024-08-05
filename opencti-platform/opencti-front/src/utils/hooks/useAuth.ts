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
  scos: { id: string, label: string }[]
  sdos: { id: string, label: string }[]
  smos: { id: string, label: string }[]
  scrs: { id: string, label: string }[]
  schemaRelationsTypesMapping: Map<string, readonly string[]>
  schemaRelationsRefTypesMapping: Map<string, readonly { readonly name: string, readonly toTypes: readonly string[] }[]>
  filterKeysSchema: Map<string, Map<string, FilterDefinition>>
};

type OverviewLayoutCustomization = Map<string, { key: string, width: number, label: string }[]>;

export interface UserContextType {
  me: RootMe_data$data | undefined;
  settings: RootSettings$data | undefined;
  bannerSettings: BannerSettings | undefined;
  entitySettings: RootPrivateQuery$data['entitySettings'] | undefined;
  platformModuleHelpers: ModuleHelper | undefined;
  schema: SchemaType | undefined;
  overviewLayoutCustomization: OverviewLayoutCustomization | undefined;
}

const defaultContext = {
  me: undefined,
  settings: undefined,
  bannerSettings: undefined,
  entitySettings: undefined,
  platformModuleHelpers: undefined,
  schema: undefined,
  overviewLayoutCustomization: undefined,
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
    overviewLayoutCustomization,
  } = useContext(UserContext);
  if (!me || !settings || !bannerSettings || !entitySettings || !platformModuleHelpers || !schema || !overviewLayoutCustomization) {
    throw new Error('Invalid user context !');
  }
  return { me, settings, bannerSettings, entitySettings, platformModuleHelpers, schema, overviewLayoutCustomization };
};

export default useAuth;
