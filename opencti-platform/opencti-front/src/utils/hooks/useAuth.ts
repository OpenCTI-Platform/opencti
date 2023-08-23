import React, { useContext } from 'react';
import { RootPrivateQuery$data } from '../../private/__generated__/RootPrivateQuery.graphql';
import { ModuleHelper } from '../platformModulesHelper';

export interface BannerSettings {
  bannerLevel?: string | null;
  bannerText?: string | null;
  idleLimit: number;
  sessionLimit: number;
  bannerHeight: string;
  bannerHeightNumber: number;
}

export interface UserContextType {
  me: RootPrivateQuery$data['me'] | undefined;
  settings: RootPrivateQuery$data['settings'] | undefined;
  bannerSettings: BannerSettings | undefined;
  entitySettings: RootPrivateQuery$data['entitySettings'] | undefined;
  platformModuleHelpers: ModuleHelper | undefined;
  schema: {
    scos: { id: string, label: string }[]
    sdos: { id: string, label: string }[]
    sros: { id: string, label: string }[]
    schemaRelationsTypesMapping: Map<string, readonly string[]>
  } | undefined;
}

const defaultContext = {
  me: undefined,
  settings: undefined,
  bannerSettings: undefined,
  entitySettings: undefined,
  platformModuleHelpers: undefined,
  schema: undefined,
};
export const UserContext = React.createContext<UserContextType>(defaultContext);

const useAuth = () => {
  const { me, settings, bannerSettings, entitySettings, platformModuleHelpers, schema } = useContext(UserContext);
  if (!me || !settings || !bannerSettings || !entitySettings || !platformModuleHelpers || !schema) {
    throw new Error('Invalid user context !');
  }
  return { me, settings, bannerSettings, entitySettings, platformModuleHelpers, schema };
};

export default useAuth;
