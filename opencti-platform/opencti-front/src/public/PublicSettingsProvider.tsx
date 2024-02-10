import { createFragmentContainer, graphql } from 'react-relay';
import React, { ReactNode, createContext, useContext } from 'react';
import { PublicSettingsProvider_settings$data } from './__generated__/PublicSettingsProvider_settings.graphql';

interface PublicSettingsContextType {
  settings?: PublicSettingsProvider_settings$data
}

const PublicSettingsContext = createContext<PublicSettingsContextType>({});

interface PublicSettingsProviderProps {
  children: ReactNode
  settings: PublicSettingsProvider_settings$data
}

const PublicSettingsProvider = createFragmentContainer(
  ({ children, settings }: PublicSettingsProviderProps) => {
    return (
      <PublicSettingsContext.Provider value={{ settings }}>
        {children}
      </PublicSettingsContext.Provider>
    );
  },
  {
    settings: graphql`
      fragment PublicSettingsProvider_settings on Settings {
        platform_map_tile_server_light
        platform_map_tile_server_dark
      }
    `,
  },
);

export const usePublicSettings = () => {
  return useContext(PublicSettingsContext);
};

export default PublicSettingsProvider;
