import React, { useContext } from 'react';
import { RootPrivateQuery$data } from '../../private/__generated__/RootPrivateQuery.graphql';
import { ModuleHelper } from '../platformModulesHelper';

export interface UserContextType {
  me: RootPrivateQuery$data['me'] | undefined;
  settings: RootPrivateQuery$data['settings'] | undefined;
  entitySettings: RootPrivateQuery$data['entitySettings'] | undefined;
  platformModuleHelpers: ModuleHelper | undefined;
  schema: {
    scos: { id: string, label: string }[]
    sdos: { id: string, label: string }[]
    sros: { id: string, label: string }[]
  } | undefined;
}

const defaultContext = {
  me: undefined,
  settings: undefined,
  entitySettings: undefined,
  platformModuleHelpers: undefined,
  schema: undefined,
};
export const UserContext = React.createContext<UserContextType>(defaultContext);

const useAuth = () => {
  const { me, settings, entitySettings, platformModuleHelpers, schema } = useContext(UserContext);
  if (!me || !settings || !entitySettings || !platformModuleHelpers || !schema) {
    throw new Error('Invalid user context !');
  }
  return { me, settings, entitySettings, platformModuleHelpers, schema };
};

export default useAuth;
