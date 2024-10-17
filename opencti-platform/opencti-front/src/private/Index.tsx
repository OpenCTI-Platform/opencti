import React, { lazy, Suspense, useEffect } from 'react';
import { Route, Routes } from 'react-router-dom';
import Box from '@mui/material/Box';
import CssBaseline from '@mui/material/CssBaseline';
import { useTheme } from '@mui/styles';
import { boundaryWrapper, NoMatch } from '@components/Error';
import PlatformCriticalAlertDialog from '@components/settings/platform_alerts/PlatformCriticalAlertDialog';
import DraftContextBanner from '@components/drafts/DraftContextBanner';
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
const DraftEntities = lazy(() => import('./components/drafts/DraftEntities'));
const StixObjectOrStixRelationship = lazy(() => import('./components/StixObjectOrStixRelationship'));
const SearchBulk = lazy(() => import('./components/SearchBulk'));
const RootAnalyses = lazy(() => import('./components/analyses/Root'));
const RootCases = lazy(() => import('./components/cases/Root'));
const RootEvents = lazy(() => import('./components/events/Root'));
const RootObservations = lazy(() => import('./components/observations/Root'));
const RootProfile = lazy(() => import('./components/profile/Root'));
const RootSearch = lazy(() => import('@components/RootSearch'));
const RootThreats = lazy(() => import('./components/threats/Root'));
const RootArsenal = lazy(() => import('./components/arsenal/Root'));
const RootTechnique = lazy(() => import('./components/techniques/Root'));
const RootEntities = lazy(() => import('./components/entities/Root'));
const RootLocation = lazy(() => import('./components/locations/Root'));
const RootData = lazy(() => import('./components/data/Root'));
const RootTrash = lazy(() => import('./components/trash/Root'));
const RootDrafts = lazy(() => import('./components/drafts/Root'));
const RootWorkspaces = lazy(() => import('./components/workspaces/Root'));
const RootSettings = lazy(() => import('./components/settings/Root'));
const RootAudit = lazy(() => import('./components/settings/activity/audit/Root'));

interface IndexProps {
  settings: RootSettings$data
}

const Index = ({ settings }: IndexProps) => {
  const theme = useTheme<Theme>();
  const {
    bannerSettings: { bannerHeight },
    me,
  } = useAuth();
  const settingsMessagesBannerHeight = useSettingsMessagesBannerHeight();
  const boxSx = {
    flexGrow: 1,
    paddingLeft: 3,
    paddingRight: 3,
    paddingBottom: 1,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.easeInOut,
      duration: theme.transitions.duration.enteringScreen,
    }),
    overflowY: 'hidden',
    minHeight: '100vh',
    paddingTop: `calc( 16px + 64px + ${settingsMessagesBannerHeight ?? 0}px)`, // 24 for margin, 48 for top bar
  };
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
      {(settings.platform_session_idle_timeout ?? 0) > 0 && <TimeoutLock />}
      <SettingsMessagesBanner />
      <PlatformCriticalAlertDialog alerts={settings.platform_critical_alerts}/>
      {me.workspace_context && (
        <DraftContextBanner />
      )}
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
          <Suspense fallback={<Loader />}>
            <Routes>
              <Route path="/" Component={me.workspace_context ? boundaryWrapper(DraftEntities) : boundaryWrapper(Dashboard)}/>

              {/* Search need to be rework */}
              <Route path="/search/*" Component={boundaryWrapper(RootSearch)} />
              <Route path="/id/:id" Component={boundaryWrapper(StixObjectOrStixRelationship)} />
              <Route path="/search_bulk" Component={boundaryWrapper(SearchBulk)} />
              <Route path="/analyses/*" Component={boundaryWrapper(RootAnalyses)} />
              <Route path="/cases/*" Component={boundaryWrapper(RootCases)} />
              <Route path="/events/*" Component={boundaryWrapper(RootEvents)} />
              <Route path="/threats/*" Component={boundaryWrapper(RootThreats)} />
              <Route path="/arsenal/*" Component={boundaryWrapper(RootArsenal)} />
              <Route path="/techniques/*" Component={boundaryWrapper(RootTechnique)} />
              {/* Need to refactor below */}
              <Route
                path="/entities/*"
                Component={boundaryWrapper(RootEntities)}
              />
              <Route
                path="/locations/*"
                Component={boundaryWrapper(RootLocation)}
              />
              <Route path="/data/*"
                Component={boundaryWrapper(RootData)}
              />
              <Route path="/trash/*"
                Component={boundaryWrapper(RootTrash)}
              />
              <Route path="/drafts/*"
                Component={boundaryWrapper(RootDrafts)}
              />
              <Route
                path="/workspaces/*"
                Component={boundaryWrapper(RootWorkspaces)}
              />
              <Route
                path="/settings/*"
                Component={boundaryWrapper(RootSettings)}
              />
              <Route
                path="/audits/*"
                Component={boundaryWrapper(RootAudit)}
              />
              <Route
                path="/profile/*"
                Component={boundaryWrapper(RootProfile)}
              />
              <Route
                path="/observations/*"
                Component={boundaryWrapper(RootObservations)}
              />
              <Route
                element={<NoMatch/>}
              />
            </Routes>
          </Suspense>
        </Box>
      </Box>
    </>
  );
};

export default Index;
