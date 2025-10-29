import React from 'react';
import CssBaseline from '@mui/material/CssBaseline';
import { StyledEngineProvider } from '@mui/material/styles';
import { loadQuery, usePreloadedQuery } from 'react-relay';
import { Route, Routes } from 'react-router-dom';
import { boundaryWrapper } from '@components/Error';
import { ConnectedThemeProvider } from '../components/AppThemeProvider';
import { ConnectedIntlProvider } from '../components/AppIntlProvider';
import { environment } from '../relay/environment';
import { rootPublicQuery } from './LoginRoot';
import { LoginRootPublicQuery } from './__generated__/LoginRootPublicQuery.graphql';
import PublicDataSharing from './components/PublicDataSharing';
import PublicDashboard from './components/PublicDashboard';
import PublicSettingsProvider from './PublicSettingsProvider';
import Message from '../components/Message';
import Playground from './components/Playground';
import { AppDataProvider } from '../utils/hooks/useAppData';

const queryRef = loadQuery<LoginRootPublicQuery>(
  environment,
  rootPublicQuery,
  {},
);

const PublicRoot = () => {
  const { publicSettings: settings } = usePreloadedQuery<LoginRootPublicQuery>(
    rootPublicQuery,
    queryRef,
  );

  const isPlaygroundEnabled = settings.playground_enabled;
  // make array mutable for the rest of the app
  const metricsDefinition = Array.from(settings.metrics_definition ?? []);

  return (
    <PublicSettingsProvider settings={settings}>
      <StyledEngineProvider injectFirst={true}>
        <ConnectedThemeProvider settings={settings}>
          <ConnectedIntlProvider settings={settings}>
            <AppDataProvider
              isPublicRoute={true}
              metricsDefinition={metricsDefinition}
            >
              <CssBaseline />
              <Message />
              <Routes>
                <Route path="/" element={boundaryWrapper(PublicDataSharing)} />
                <Route path="/dashboard/:uriKey/*" element={boundaryWrapper(PublicDashboard)} />
                {isPlaygroundEnabled && <Route path="/graphql/" element={boundaryWrapper(Playground)}/>}
              </Routes>
            </AppDataProvider>
          </ConnectedIntlProvider>
        </ConnectedThemeProvider>
      </StyledEngineProvider>
    </PublicSettingsProvider>
  );
};

export default PublicRoot;
