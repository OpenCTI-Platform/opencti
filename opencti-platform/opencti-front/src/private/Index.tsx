import React, { lazy, Suspense, useEffect } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import Box from '@mui/material/Box';
import CssBaseline from '@mui/material/CssBaseline';
import { useTheme } from '@mui/styles';
import { boundaryWrapper, NoMatch } from '@components/Error';
import PlatformCriticalAlertDialog from '@components/settings/platform_alerts/PlatformCriticalAlertDialog';
import LicenceBanner from '@components/LicenceBanner';
import StartTrialBanner from '@components/xtm_hub/StartTrialBanner';
import TopBar from './components/nav/TopBar';
import LeftBar from './components/nav/LeftBar';
import Message from '../components/Message';
import SystemBanners from '../public/components/SystemBanners';
import TimeoutLock from './components/TimeoutLock';
import useAuth from '../utils/hooks/useAuth';
import useHelper from '../utils/hooks/useHelper';
import SettingsMessagesBanner, { useSettingsMessagesBannerHeight } from './components/settings/settings_messages/SettingsMessagesBanner';
import type { Theme } from '../components/Theme';
import { RootSettings$data } from './__generated__/RootSettings.graphql';
import Loader from '../components/Loader';
import useDraftContext from '../utils/hooks/useDraftContext';

const Dashboard = lazy(() => import('./components/Dashboard'));
const StixObjectOrStixRelationship = lazy(() => import('./components/StixObjectOrStixRelationship'));
const RootSearchBulk = lazy(() => import('./components/SearchBulkContainer'));
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
const RootPir = lazy(() => import('./components/pir/Root'));
const RootXTMHub = lazy(() => import('@components/xtm_hub/Root'));

interface IndexProps {
  settings: RootSettings$data
}

const Index = ({ settings }: IndexProps) => {
  const theme = useTheme<Theme>();
  const { isTrashEnable, isFeatureEnable } = useHelper();
  const {
    bannerSettings: { bannerHeight },
  } = useAuth();
  const draftContext = useDraftContext();
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
  const featureFlagFreeTrials = isFeatureEnable('FREE_TRIALS');

  return (
    <>
      <SystemBanners settings={settings} />
      {featureFlagFreeTrials && <LicenceBanner />}
      {featureFlagFreeTrials && <StartTrialBanner />}
      {(settings.platform_session_idle_timeout ?? 0) > 0 && <TimeoutLock />}
      <SettingsMessagesBanner />
      <PlatformCriticalAlertDialog alerts={settings.platform_critical_alerts}/>
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
              <Route path="/" element={draftContext?.id
                ? (
                  <Navigate to={`/dashboard/data/import/draft/${draftContext.id}/`} replace={true}/>
                )
                : boundaryWrapper(Dashboard)}
              />
              {/* Search need to be rework */}
              <Route path="/search/*" element={boundaryWrapper(RootSearch)} />
              <Route path="/id/:id" element={boundaryWrapper(StixObjectOrStixRelationship)} />
              <Route path="/search_bulk" element={boundaryWrapper(RootSearchBulk)} />
              <Route path="/analyses/*" element={boundaryWrapper(RootAnalyses)} />
              <Route path="/cases/*" element={boundaryWrapper(RootCases)} />
              <Route path="/events/*" element={boundaryWrapper(RootEvents)} />
              <Route path="/threats/*" element={boundaryWrapper(RootThreats)} />
              <Route path="/arsenal/*" element={boundaryWrapper(RootArsenal)} />
              <Route path="/techniques/*" element={boundaryWrapper(RootTechnique)} />
              {/* Need to refactor below */}
              <Route path="/entities/*" element={boundaryWrapper(RootEntities)}/>
              <Route path="/locations/*" element={boundaryWrapper(RootLocation)}/>
              <Route path="/data/import/draft/*" element={boundaryWrapper(RootDrafts)}/>
              <Route path="/data/*" element={boundaryWrapper(RootData)}/>
              {isTrashEnable() && (<Route path="/trash/*" element={boundaryWrapper(RootTrash)}/>)}
              <Route path="/pirs/*" element={boundaryWrapper(RootPir)}/>
              <Route path="/workspaces/*" element={boundaryWrapper(RootWorkspaces)}/>
              <Route path="/settings/*" element={boundaryWrapper(RootSettings)}/>
              <Route path="/audits/*" element={boundaryWrapper(RootAudit)}/>
              <Route path="/profile/*" element={boundaryWrapper(RootProfile)}/>
              <Route path="/observations/*" element={boundaryWrapper(RootObservations)}/>
              <Route path="/xtm-hub/*" element={boundaryWrapper(RootXTMHub)}/>
              <Route path="/*" element={<NoMatch/>}/>
            </Routes>
          </Suspense>
        </Box>
      </Box>
    </>
  );
};

export default Index;
