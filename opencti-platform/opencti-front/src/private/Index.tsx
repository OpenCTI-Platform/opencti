import React, { lazy, Suspense, useEffect } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import Box from '@mui/material/Box';
import CssBaseline from '@mui/material/CssBaseline';
import { useTheme } from '@mui/styles';
import { boundaryWrapper, NoMatch } from '@components/Error';
import PlatformCriticalAlertDialog from '@components/settings/platform_alerts/PlatformCriticalAlertDialog';
import { BubbleChat } from 'flowise-embed-react';
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
import useEnterpriseEdition from '../utils/hooks/useEnterpriseEdition';

const Dashboard = lazy(() => import('./components/Dashboard'));
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
const RootPir = lazy(() => import('./components/pir/Root'));

interface IndexProps {
  settings: RootSettings$data
}

const Index = ({ settings }: IndexProps) => {
  const theme = useTheme<Theme>();
  const isEnterpriseEdition = useEnterpriseEdition();
  const { isTrashEnable, isFeatureEnable } = useHelper();
  const {
    bannerSettings: { bannerHeight },
    me,
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
  const chatBoxTheme = {
    button: {
      backgroundColor: '#001BDA',
      right: 20,
      bottom: 20,
      size: 48,
      dragAndDrop: true,
      iconColor: 'white',
      customIconSrc: 'https://filigran.io/app/uploads/2025/05/ai-chat.png',
      autoWindowOpen: {
        autoOpen: false,
        openDelay: 2,
        autoOpenOnMobile: false,
      },
    },
    tooltip: {
      showTooltip: false,
    },
    customCSS: `
          * {
            font-family: "IBM Plex Sans" !important;
          }
        `,
    chatWindow: {
      showTitle: true,
      showAgentMessages: false,
      title: 'Ariane Docs Assistant',
      titleAvatarSrc:
          'https://filigran.io/app/uploads/2025/05/embleme_filigran_blanc.png',
      welcomeMessage: isEnterpriseEdition
        ? "Hi there 👋 You're speaking with an AI Agent. I'm here to answer your questions, so what brings you here today?"
        : 'Please, activate Entreprise Edition to get access to ChatBot.',
      errorMessage: 'Sorry, an error has occurred, please try again later.',
      backgroundColor: '#ffffff',
      height: 700,
      width: 400,
      fontSize: 14,
      starterPromptFontSize: 13,
      clearChatOnReload: false,
      sourceDocsTitle: 'Sources:',
      renderHTML: true,
      botMessage: {
        backgroundColor: '#f7f8ff',
        textColor: '#000000',
        showAvatar: true,
        avatarSrc:
            'https://filigran.io/app/uploads/2025/05/embleme_filigran_background.png',
      },
      userMessage: {
        backgroundColor: '#001BDA',
        textColor: '#ffffff',
        showAvatar: false,
      },
      textInput: {
        placeholder: 'Ask a question...',
        backgroundColor: '#ffffff',
        textColor: '#303235',
        sendButtonColor: '#001BDA',
        maxChars: 100,
        maxCharsWarningMessage:
            'You exceeded the characters limit. Please input less than 50 characters.',
        autoFocus: true,
        sendMessageSound: false,
        receiveMessageSound: false,
      },
      dateTimeToggle: {
        date: true,
        time: true,
      },
      footer: {
        textColor: '#303235',
        text: 'Powered by',
        company: 'Filigran Ariane AI',
        companyLink: 'https://filigran.io',
      },
    },
  };
  const chartFlowConfigVars = {
    vars: {
      OPENCTI_URL: settings.platform_url,
      OPENCTI_TOKEN: me.api_token,
    },
  };
  return (
    <>
      <SystemBanners settings={settings} />
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
        <BubbleChat
          chatflowid={settings.platform_ai_flow_id ?? ''}
          apiHost={settings.platform_api_host ?? ''}
          chatflowConfig={chartFlowConfigVars}
          theme={chatBoxTheme}
        />
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
              <Route path="/search_bulk" element={boundaryWrapper(SearchBulk)} />
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
              {isFeatureEnable('Pir') && <Route path="/pirs/*" element={boundaryWrapper(RootPir)}/>}
              <Route path="/workspaces/*" element={boundaryWrapper(RootWorkspaces)}/>
              <Route path="/settings/*" element={boundaryWrapper(RootSettings)}/>
              <Route path="/audits/*" element={boundaryWrapper(RootAudit)}/>
              <Route path="/profile/*" element={boundaryWrapper(RootProfile)}/>
              <Route path="/observations/*" element={boundaryWrapper(RootObservations)}/>
              <Route path="/*" element={<NoMatch/>}/>
            </Routes>
          </Suspense>
        </Box>
      </Box>
    </>
  );
};

export default Index;
