import React, { useEffect } from 'react';
import { Route, Switch } from 'react-router-dom';
import makeStyles from '@mui/styles/makeStyles';
import Box from '@mui/material/Box';
import CssBaseline from '@mui/material/CssBaseline';
import { useTheme } from '@mui/styles';
import { BoundaryRoute, NoMatch } from '@components/Error';
import Search from './components/Search';
import TopBar from './components/nav/TopBar';
import LeftBar from './components/nav/LeftBar';
import Dashboard from './components/Dashboard';
import RootImport from './components/import/Root';
import RootAnalyses from './components/analyses/Root';
import RootEvents from './components/events/Root';
import RootObservations from './components/observations/Root';
import RootThreats from './components/threats/Root';
import RootArsenal from './components/arsenal/Root';
import RootTechnique from './components/techniques/Root';
import RootEntities from './components/entities/Root';
import RootLocation from './components/locations/Root';
import RootSettings from './components/settings/Root';
import RootActivity from './components/settings/activity/Root';
import RootNotifications from './components/profile/Root';
import RootData from './components/data/Root';
import RootWorkspaces from './components/workspaces/Root';
import Message from '../components/Message';
import StixObjectOrStixRelationship from './components/StixObjectOrStixRelationship';
import SearchBulk from './components/SearchBulk';
import RootCases from './components/cases/Root';
import SystemBanners from '../public/components/SystemBanners';
import TimeoutLock from './components/TimeoutLock';
import useAuth from '../utils/hooks/useAuth';
import SettingsMessagesBanner, { useSettingsMessagesBannerHeight } from './components/settings/settings_messages/SettingsMessagesBanner';
import { Theme } from '../components/Theme';
import { RootPrivateQuery$data } from './__generated__/RootPrivateQuery.graphql';

const useStyles = makeStyles((theme: Theme) => ({
  toolbar: theme.mixins.toolbar,
}));

interface IndexProps {
  settings: RootPrivateQuery$data['settings']
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
          <Switch>
            <BoundaryRoute exact path="/dashboard" component={Dashboard} />
            <BoundaryRoute exact path="/dashboard/search" component={Search} />
            <BoundaryRoute
              exact
              path="/dashboard/search/:keyword"
              component={Search}
            />
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
            <BoundaryRoute path="/dashboard/data" render={RootData} />
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
              component={RootNotifications}
            />
            <Route
              // Because mismatch of types between react-router v5 and v6.
              // It uses types of v6, but we are using v5 here and compiler is lost.
              /* eslint-disable-next-line @typescript-eslint/ban-ts-comment */
              /* @ts-ignore */
              component={NoMatch}
            />
          </Switch>
        </Box>
      </Box>
    </>
  );
};

export default Index;
