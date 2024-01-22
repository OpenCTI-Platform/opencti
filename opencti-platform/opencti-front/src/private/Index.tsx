import React, { Suspense, lazy, useEffect } from 'react';
import { Route, Switch } from 'react-router-dom';
import Box from '@mui/material/Box';
import CssBaseline from '@mui/material/CssBaseline';
import { useTheme, makeStyles } from '@mui/styles';
import { BoundaryRoute, NoMatch } from '@components/Error';
import PlatformCriticalAlertBanner from '@components/settings/platform_alerts/PlatformCriticalAlertBanner';
import TopBar from './components/nav/TopBar';
import LeftBar from './components/nav/LeftBar';
import Message from '../components/Message';
import SystemBanners from '../public/components/SystemBanners';
import TimeoutLock from './components/TimeoutLock';
import useAuth from '../utils/hooks/useAuth';
import SettingsMessagesBanner, { useSettingsMessagesBannerHeight } from './components/settings/settings_messages/SettingsMessagesBanner';
import type { Theme } from '../components/Theme';
import { RootSettings$data } from './__generated__/RootSettings.graphql';
import Loader from '../components/Loader';

const Dashboard = lazy(() => import('./components/Dashboard'));
const SearchRoot = lazy(() => import('@components/SearchRoot'));
const StixObjectOrStixRelationship = lazy(() => import('./components/StixObjectOrStixRelationship'));
const SearchBulk = lazy(() => import('./components/SearchBulk'));
const RootAnalyses = lazy(() => import('./components/analyses/Root'));
const RootCases = lazy(() => import('./components/cases/Root'));
const RootEvents = lazy(() => import('./components/events/Root'));
const RootObservations = lazy(() => import('./components/observations/Root'));
const RootThreats = lazy(() => import('./components/threats/Root'));
const RootArsenal = lazy(() => import('./components/arsenal/Root'));
const RootTechnique = lazy(() => import('./components/techniques/Root'));
const RootEntities = lazy(() => import('./components/entities/Root'));
const RootLocation = lazy(() => import('./components/locations/Root'));
const RootData = lazy(() => import('./components/data/Root'));
const RootWorkspaces = lazy(() => import('./components/workspaces/Root'));
const RootSettings = lazy(() => import('./components/settings/Root'));
const RootActivity = lazy(() => import('./components/settings/activity/Root'));
const RootImport = lazy(() => import('./components/import/Root'));
const RootProfile = lazy(() => import('./components/profile/Root'));

const useStyles = makeStyles((theme: Theme) => ({
  toolbar: theme.mixins.toolbar,
}));

interface IndexProps {
  settings: RootSettings$data
}

const Index = ({ settings }: IndexProps) => {
  const theme = useTheme<Theme>();
  const classes = useStyles();
  const {
    bannerSettings: { bannerHeight },
  } = useAuth();
  const boxSx = {
    flexGrow: 1,
    padding: 3,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.easeInOut,
      duration: theme.transitions.duration.enteringScreen,
    }),
    overflowX: 'hidden',
  };
  const settingsMessagesBannerHeight = useSettingsMessagesBannerHeight();
  // Change the theme body attribute when the mode changes in
  // the palette because some components like CKEditor uses this
  // body attribute to display correct styles.
  useEffect(() => {
    const body = document.querySelector('body');
    if (body) {
      const bodyMode = body.getAttribute('data-theme');
      const themeMode = `${theme.palette.mode}`;
      if (bodyMode !== themeMode) {
        body.setAttribute('data-theme', themeMode);
      }
    }
  }, [theme]);
  return (
    <>
      <SystemBanners settings={settings} />
      {(settings?.platform_session_idle_timeout ?? 0) > 0 && <TimeoutLock />}
      <SettingsMessagesBanner />
      <PlatformCriticalAlertBanner alerts={settings.platform_critical_alerts}/>
      <Box
        sx={{
          display: 'flex',
          minWidth: 1400,
          marginTop: bannerHeight,
          marginBottom: bannerHeight,
        }}
      >
        <CssBaseline />
        <TopBar />
        <LeftBar />
        <Message />
        <Box component="main" sx={boxSx}>
          <div
            className={classes.toolbar}
            style={{ marginTop: settingsMessagesBannerHeight }}
          />
          <Suspense fallback={<Loader />}>
            <Switch>
              <BoundaryRoute exact path="/dashboard" component={Dashboard} />
              <BoundaryRoute exact path="/dashboard/search" component={SearchRoot} />
              <BoundaryRoute exact path="/dashboard/search/:scope" component={SearchRoot} />
              <BoundaryRoute exact path="/dashboard/search/:scope/:keyword" component={SearchRoot} />
              <BoundaryRoute
                exact
                path="/dashboard/id/:id"
                component={StixObjectOrStixRelationship}
              />
              <BoundaryRoute
                exact
                path="/dashboard/search_bulk"
                component={SearchBulk}
              />
              <BoundaryRoute
                path="/dashboard/analyses"
                component={RootAnalyses}
              />
              <BoundaryRoute path="/dashboard/cases" component={RootCases} />
              <BoundaryRoute path="/dashboard/events" component={RootEvents} />
              <Route
                path="/dashboard/observations"
              // Because mismatch of types between react-router v5 and v6.
              // It uses types of v6, but we are using v5 here and compiler is lost.
              /* eslint-disable-next-line @typescript-eslint/ban-ts-comment */
              /* @ts-ignore */
                component={RootObservations}
              />
              <BoundaryRoute path="/dashboard/threats" component={RootThreats} />
              <BoundaryRoute path="/dashboard/arsenal" component={RootArsenal} />
              <BoundaryRoute
                path="/dashboard/techniques"
                component={RootTechnique}
              />
              <BoundaryRoute
                path="/dashboard/entities"
                component={RootEntities}
              />
              <BoundaryRoute
                path="/dashboard/locations"
                component={RootLocation}
              />
              <BoundaryRoute path="/dashboard/data" component={RootData} />
              <BoundaryRoute
                path="/dashboard/workspaces"
                component={RootWorkspaces}
              />
              <BoundaryRoute
                path="/dashboard/settings"
                component={RootSettings}
              />
              <BoundaryRoute path="/dashboard/audits" component={RootActivity} />
              <BoundaryRoute path="/dashboard/import" component={RootImport} />
              <BoundaryRoute
                path="/dashboard/profile"
                component={RootProfile}
              />
              <Route
              // Because mismatch of types between react-router v5 and v6.
              // It uses types of v6, but we are using v5 here and compiler is lost.
              /* eslint-disable-next-line @typescript-eslint/ban-ts-comment */
              /* @ts-ignore */
                component={NoMatch}
              />
            </Switch>
          </Suspense>
        </Box>
      </Box>
    </>
  );
};

export default Index;
