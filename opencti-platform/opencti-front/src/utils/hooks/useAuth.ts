import React, { useContext } from 'react';
import { RootPrivateQuery$data } from '../../private/__generated__/RootPrivateQuery.graphql';
import { ModuleHelper } from '../platformModulesHelper';

export interface UserContextType {
  me: RootPrivateQuery$data['me'] | undefined;
  settings: RootPrivateQuery$data['settings'] | undefined;
  entitySettings: RootPrivateQuery$data['entitySettings'] | undefined;
  helper: ModuleHelper | undefined;
}

const defaultContext = {
  me: undefined,
  settings: undefined,
  entitySettings: undefined,
  helper: undefined,
};
export const UserContext = React.createContext<UserContextType>(defaultContext);

const useAuth = () => {
  const { me, settings, entitySettings } = useContext(UserContext);
  if (!me || !settings || !entitySettings) {
    throw new Error('Invalid user context !');
  }
  return { me, settings, entitySettings };
};

export default useAuth;
