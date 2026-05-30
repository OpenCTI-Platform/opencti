import React, { useEffect, useState } from 'react';
import { createPortal } from 'react-dom';
import { ChatPanel, ChatMode } from '@filigran/chatbot';
import { useLocation, useNavigate } from 'react-router-dom';
import { useTheme } from '@mui/styles';
import { LogoXtmOneIcon } from 'filigran-icon';
import type { Theme } from '../../../components/Theme';
import { useFormatter } from '../../../components/i18n';
import useAuth from '../../../utils/hooks/useAuth';
import { APP_BASE_PATH } from '../../../relay/environment';
import { useSettingsMessagesBannerHeight } from '../settings/settings_messages/SettingsMessagesBanner';
import useTopBanner from '../../../utils/hooks/useTopBanner';
import FiligranIcon from '@components/common/FiligranIcon';

const TOP_BAR_HEIGHT = 64;

interface AskArianePanelProps {
  mode: ChatMode;
  onClose: () => void;
  onModeChange: (mode: ChatMode) => void;
  onWidthChange?: (width: number) => void;
  onResizeStart?: () => void;
  onResizeEnd?: () => void;
}

const AskArianePanel: React.FC<AskArianePanelProps> = ({
  mode,
  onClose,
  onModeChange,
  onWidthChange,
  onResizeStart,
  onResizeEnd,
}) => {
  const navigate = useNavigate();
  const location = useLocation();
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { me, bannerSettings: { bannerHeightNumber } } = useAuth();
  const settingsMessagesBannerHeight = useSettingsMessagesBannerHeight();
  const { height: topBannerHeight } = useTopBanner();
  const [container, setContainer] = useState<HTMLDivElement | null>(null);
  const [xtmOneUrl, setXtmOneUrl] = useState<string | null>(null);

  // Stack all the floating banners that sit above the top bar so the chatbot
  // panel sticks right under the actual top bar in every configuration.
  // See `TopBar.tsx` which uses the same sum to offset its toolbar.
  const topOffset = TOP_BAR_HEIGHT
    + bannerHeightNumber
    + topBannerHeight
    + settingsMessagesBannerHeight;

  const firstName = me.user_email?.split('@')[0] ?? 'User';

  const accentColor = theme.palette.ai?.main ?? '#7b5cff';

  const logoIcon = (
    <FiligranIcon
      icon={LogoXtmOneIcon}
      size="small"
      style={{ color: 'inherit' }}
    />
  );

  const isDarkMode = theme.palette.mode === 'dark';

  const promptSuggestions = [
    t_i18n('What are the latest threats?'),
    t_i18n('Show me recent reports'),
    t_i18n('Analyze this indicator'),
  ];

  const draftId = me.draftContext?.id;
  const requestHeaders = draftId ? { 'opencti-draft-id': draftId } : undefined;
  const draftBorderColor = draftId
    ? theme.palette.designSystem.alert.warning.primary
    : undefined;

  // Forward the user's current in-app location so the agent is always aware
  // of the page (URI) the question is being asked from. The router uses
  // `basename={APP_BASE_PATH}`, so `location.pathname` is already
  // app-relative (e.g. `/dashboard/analyses/reports/<id>/overview`). The
  // shape is intentionally extensible — more context (page title, selected
  // entity, etc.) can be added here later.
  const pageContext = { url: `${location.pathname}${location.search}` };

  const handleRelativeLinkClick = (href: string) => {
    const normalizedHref = APP_BASE_PATH && href.startsWith(APP_BASE_PATH)
      ? href.slice(APP_BASE_PATH.length) || '/'
      : href;
    navigate(normalizedHref);
  };

  useEffect(() => {
    fetch(`${APP_BASE_PATH}/chatbot/config`)
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (data?.xtm_one_url) setXtmOneUrl(data.xtm_one_url);
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    const div = document.createElement('div');
    div.id = 'ask-ariane-portal';
    div.className = isDarkMode ? 'dark' : '';
    document.body.appendChild(div);
    setContainer(div);

    return () => {
      document.body.removeChild(div);
    };
  }, []);

  useEffect(() => {
    if (container) {
      container.className = isDarkMode ? 'dark' : '';
    }
  }, [isDarkMode, container]);

  if (!container) {
    return null;
  }

  return createPortal(
    <ChatPanel
      mode={mode}
      onClose={onClose}
      onModeChange={onModeChange}
      topOffset={topOffset}
      backendType="rest"
      apiBaseUrl={`${APP_BASE_PATH}/chatbot`}
      apiEndpoints={{
        agents: '/agents',
        messages: '/messages',
        sessions: '/sessions',
        upload: '/upload',
        download: '/files',
      }}
      user={{ firstName }}
      disableFileManagement={false}
      t={t_i18n}
      accentColor={accentColor}
      logoIcon={logoIcon}
      agentDashboardUrl={xtmOneUrl || undefined}
      promptSuggestions={promptSuggestions}
      draftBorderColor={draftBorderColor}
      resizable={mode === 'sidebar'}
      onWidthChange={onWidthChange}
      onResizeStart={onResizeStart}
      onResizeEnd={onResizeEnd}
      requestHeaders={requestHeaders}
      pageContext={pageContext}
      onRelativeLinkClick={handleRelativeLinkClick}
    />,
    container,
  );
};

export default AskArianePanel;
