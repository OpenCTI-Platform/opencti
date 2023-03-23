import React, { useContext } from 'react';
import { RootPrivateQuery$data } from '../../private/__generated__/RootPrivateQuery.graphql';
import { ModuleHelper } from '../platformModulesHelper';

export interface UserContextType {
  me: RootPrivateQuery$data['me'] | undefined;
  settings: RootPrivateQuery$data['settings'] | undefined;
  entitySettings: RootPrivateQuery$data['entitySettings'] | undefined;
  platformModuleHelpers: ModuleHelper | undefined;
}

const defaultContext = {
  me: undefined,
  settings: undefined,
  entitySettings: undefined,
  platformModuleHelpers: undefined,
};
export const UserContext = React.createContext<UserContextType>(defaultContext);

const useAuth = () => {
  const { me, settings, entitySettings, platformModuleHelpers } = useContext(UserContext);
  if (!me || !settings || !entitySettings || !platformModuleHelpers) {
    throw new Error('Invalid user context !');
  }
  return { me, settings, entitySettings, platformModuleHelpers };
};

export default useAuth;
