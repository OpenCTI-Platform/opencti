import React from 'react';
import CssBaseline from '@mui/material/CssBaseline';
import { StyledEngineProvider } from '@mui/material/styles';
import { TooltipProvider } from '@filigran/design-system';
import { loadQuery, usePreloadedQuery } from 'react-relay';
import { Route, Routes } from 'react-router';
import { boundaryWrapper } from '@components/Error';
import { ConnectedThemeProvider } from '../components/AppThemeProvider';
import { ConnectedIntlProvider } from '../components/AppIntlProvider';
import { environment } from '../relay/environment';
import { rootPublicQuery } from './LoginRoot';
import { LoginRootPublicQuery } from './__generated__/LoginRootPublicQuery.graphql';
import PublicDataSharing from './components/PublicDataSharing';
import PublicDashboard from './components/PublicDashboard';
import Message from '../components/Message';
import Playground from './components/Playground';
import { AppDataProvider } from '../utils/hooks/useAppData';
import { TOOLTIP_DELAY_MS } from '../private/components/nav/topBarConstants';

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
    <StyledEngineProvider injectFirst={true}>
      <ConnectedThemeProvider settings={settings}>
        <ConnectedIntlProvider settings={settings}>
          <AppDataProvider
            isPublicRoute={true}
            metricsDefinition={metricsDefinition}
          >
            <CssBaseline />
            <Message />
            {/* The tooltips of the design system, with the delay of the application */}
            <TooltipProvider delayDuration={TOOLTIP_DELAY_MS}>
              <Routes>
                <Route path="/" element={boundaryWrapper(PublicDataSharing)} />
                <Route path="/dashboard/:uriKey/*" element={boundaryWrapper(PublicDashboard)} />
                {isPlaygroundEnabled && <Route path="/graphql/" element={boundaryWrapper(Playground)} />}
              </Routes>
            </TooltipProvider>
          </AppDataProvider>
        </ConnectedIntlProvider>
      </ConnectedThemeProvider>
    </StyledEngineProvider>
  );
};

export default PublicRoot;
