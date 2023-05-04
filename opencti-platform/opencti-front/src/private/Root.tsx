import { StyledEngineProvider } from '@mui/material/styles';
import React from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { ConnectedIntlProvider } from '../components/AppIntlProvider';
import { ConnectedThemeProvider } from '../components/AppThemeProvider';
import Loader, { LoaderVariant } from '../components/Loader';
import { useVocabularyCategoryQuery } from '../utils/hooks/__generated__/useVocabularyCategoryQuery.graphql';
import { UserContext } from '../utils/hooks/useAuth';
import useQueryLoading, { QueryContext } from '../utils/hooks/useQueryLoading';
import { vocabCategoriesQuery } from '../utils/hooks/useVocabularyCategory';
import platformModuleHelper from '../utils/platformModulesHelper';
import { RootPrivateQuery } from './__generated__/RootPrivateQuery.graphql';
import Index from './Index';

const rootPrivateQuery = graphql`
  query RootPrivateQuery {
    me {
      id
      name
      lastname
      language
      theme
      user_email
      individual_id
      capabilities {
        name
      }
      default_hidden_types
    }
    settings {
      platform_map_tile_server_dark
      platform_map_tile_server_light
      platform_theme
      platform_feature_flags {
        id
        enable
      }
      platform_modules {
        id
        enable
        running
      }
      ...AppThemeProvider_settings
      ...AppIntlProvider_settings
      ...PasswordPolicies
      ...AccessSettings
    }
    about {
      version
    }
    entitySettings {
      ...EntitySettingConnection_entitySettings
    }
  }
`;

const Root = () => {
  const data = useLazyLoadQuery<RootPrivateQuery>(rootPrivateQuery, {});
  const { me, settings, entitySettings } = data;
  // TODO : Use the hook useHelper when all project is pure function //
  const platformModuleHelpers = platformModuleHelper(settings);

  const vocabularyCategoriesQueryRef = useQueryLoading<useVocabularyCategoryQuery>(vocabCategoriesQuery, {});

  return (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      {(vocabularyCategoriesQueryRef) && (
        <QueryContext.Provider value={{ vocabularyCategoriesQueryRef }}>
          <UserContext.Provider value={{ me, settings, entitySettings, platformModuleHelpers }}>
            <StyledEngineProvider injectFirst={true}>
              <ConnectedThemeProvider settings={settings}>
                <ConnectedIntlProvider settings={settings}>
                  <Index />
                </ConnectedIntlProvider>
              </ConnectedThemeProvider>
            </StyledEngineProvider>
          </UserContext.Provider>
        </QueryContext.Provider>
      )}
    </React.Suspense>
  );
};

export default Root;
