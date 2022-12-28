import React, { useContext } from 'react';
import { RootPrivateQuery$data } from '../../private/__generated__/RootPrivateQuery.graphql';
import { ModuleHelper } from '../platformModulesHelper';

export interface UserContextType {
  me: RootPrivateQuery$data['me'] | undefined;
  settings: RootPrivateQuery$data['settings'] | undefined;
  helper: ModuleHelper | undefined;
}

const defaultContext = {
  me: undefined,
  settings: undefined,
  helper: undefined,
};
export const UserContext = React.createContext<UserContextType>(defaultContext);

const useAuth = () => {
  const { me, settings } = useContext(UserContext);
  if (!me || !settings) {
    throw new Error('Invalid user context !');
  }
  return { me, settings };
};

export default useAuth;
