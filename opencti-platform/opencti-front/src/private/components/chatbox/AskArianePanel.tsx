import React, { useEffect, useState } from 'react';
import { createPortal } from 'react-dom';
import { ChatPanel, ChatMode } from '@filigran/chatbot';
import { useTheme } from '@mui/styles';
import { LogoXtmOneIcon } from 'filigran-icon';
import type { Theme } from '../../../components/Theme';
import { useFormatter } from '../../../components/i18n';
import useAuth from '../../../utils/hooks/useAuth';
import { APP_BASE_PATH } from '../../../relay/environment';
import { useSettingsMessagesBannerHeight } from '../settings/settings_messages/SettingsMessagesBanner';
import FiligranIcon from '@components/common/FiligranIcon';

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
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { me } = useAuth();
  const settingsMessagesBannerHeight = useSettingsMessagesBannerHeight();
  const [container, setContainer] = useState<HTMLDivElement | null>(null);

  const topOffset = 64 + settingsMessagesBannerHeight;

  const firstName = me.user_email?.split('@')[0] ?? 'User';

  const accentColor = theme.palette.ai?.main ?? '#7b5cff';

  const logoIcon = (
    <FiligranIcon
      icon={LogoXtmOneIcon}
      size="small"
      style={{ color: 'white' }}
    />
  );

  const isDarkMode = theme.palette.mode === 'dark';

  const promptSuggestions = [
    t_i18n('What are the latest threats?'),
    t_i18n('Show me recent reports'),
    t_i18n('Analyze this indicator'),
  ];

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
      apiEndpoints={{ agents: '/agents', messages: '/messages', sessions: '/sessions' }}
      user={{ firstName }}
      t={t_i18n}
      accentColor={accentColor}
      logoIcon={logoIcon}
      promptSuggestions={promptSuggestions}
      resizable={mode === 'sidebar'}
      onWidthChange={onWidthChange}
      onResizeStart={onResizeStart}
      onResizeEnd={onResizeEnd}
    />,
    container,
  );
};

export default AskArianePanel;
