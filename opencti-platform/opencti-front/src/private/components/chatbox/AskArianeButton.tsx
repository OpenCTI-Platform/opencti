import { Button } from '@filigran/design-system';
import FiligranIcon from '@components/common/FiligranIcon';
import EEChip from '@components/common/entreprise_edition/EEChip';
import EETooltip from '@components/common/entreprise_edition/EETooltip';
import { CGUStatus } from '@components/settings/Experience';
import ValidateTermsOfUseDialog from '@components/settings/ValidateTermsOfUseDialog';
import { useTheme } from '@mui/styles';
import { LogoXtmOneIcon } from 'filigran-icon';
import React, { useEffect, useRef, useState } from 'react';
import type { Theme } from '../../../components/Theme';
import { useFormatter } from '../../../components/i18n';
import useAuth from '../../../utils/hooks/useAuth';
import useEnterpriseEdition from '../../../utils/hooks/useEnterpriseEdition';
import useGranted, { SETTINGS_SETPARAMETERS } from '../../../utils/hooks/useGranted';
import useHelper from '../../../utils/hooks/useHelper';
import AskArianePanel from './AskArianePanel';
import ChatbotManager from './ChatbotManager';
import { useChatbot } from './ChatbotContext';
import { useSettingsMessagesBannerHeight } from '../settings/settings_messages/SettingsMessagesBanner';
import useTopBanner from '../../../utils/hooks/useTopBanner';

const AskArianeButton = () => {
  const { t_i18n } = useFormatter();
  const { isChatbotAiEnabled } = useHelper();
  const { settings: { filigran_chatbot_ai_cgu_status }, bannerSettings: { bannerHeightNumber } } = useAuth();
  const theme = useTheme<Theme>();
  const isEnterpriseEdition = useEnterpriseEdition();
  const hasRightToValidateCGU = useGranted([SETTINGS_SETPARAMETERS]);
  const settingsMessagesBannerHeight = useSettingsMessagesBannerHeight();
  const { height: topBannerHeight } = useTopBanner();
  const {
    isOpen, mode, openChat, closeChat, setMode,
    setSidebarWidth, setIsResizing, xtmOneConfigured,
  } = useChatbot();

  const isCGUStatusPending = filigran_chatbot_ai_cgu_status === CGUStatus.pending;
  const [openValidateTermsOfUse, setOpenValidateTermsOfUse] = useState(false);

  const isChatbotEnabled = isEnterpriseEdition && isChatbotAiEnabled();
  const useLegacy = xtmOneConfigured === false;

  // Total height of all floating banners stacked above the top bar.
  // Forwarded to the legacy chatbot so its window sticks under the real top bar.
  const totalBannerHeight = bannerHeightNumber + topBannerHeight + settingsMessagesBannerHeight;

  // Legacy v1 web-component management (only active when XTM One is NOT configured)
  const chatbotManager = useRef(ChatbotManager.getInstance());

  useEffect(() => {
    if (useLegacy && isChatbotEnabled) {
      chatbotManager.current.configure(theme, t_i18n, totalBannerHeight);
    }
  }, [useLegacy, isChatbotEnabled, theme, t_i18n, totalBannerHeight]);

  useEffect(() => {
    if (useLegacy && !isChatbotEnabled && chatbotManager.current.isReady()) {
      chatbotManager.current.destroy();
    }
  }, [useLegacy, isChatbotEnabled]);

  useEffect(() => {
    if (useLegacy && chatbotManager.current.isReady()) {
      chatbotManager.current.setOnClose(closeChat);
    }
  }, [useLegacy, chatbotManager.current.isReady(), closeChat]);

  // Sync open/close with legacy ChatbotManager
  useEffect(() => {
    if (!useLegacy) return;
    if (isOpen) {
      chatbotManager.current.open();
    } else if (chatbotManager.current.isReady()) {
      chatbotManager.current.close();
    }
  }, [useLegacy, isOpen]);

  const toggleChatbot = () => {
    if (filigran_chatbot_ai_cgu_status === CGUStatus.enabled) {
      if (isOpen) {
        closeChat();
      } else {
        openChat();
      }
    } else if (hasRightToValidateCGU) {
      setOpenValidateTermsOfUse(true);
    }
  };

  return (
    <>
      {/* The EE badge sits INSIDE the button, in its trailing slot. This
          reverses the earlier "sibling at a 4px gap" ruling, at the designer's
          explicit request during the night-2 pass. `clickable={false}` is what
          makes that legal: the chip renders a plain element rather than the
          <button> it defaults to, so the surrounding control keeps owning the
          click and no button is nested inside another. The slot brings its own
          gap, so the chip's default inline-start margin is zeroed. */}
      <EETooltip
        title={isCGUStatusPending && !hasRightToValidateCGU ? t_i18n('Ask Ariane isn\'t activated yet. Please reach out to your administrator to enable this feature.') : 'Open chatbot'}
      >
        <Button
          variant="ia"
          priority="tertiary"
          onClick={toggleChatbot}
          startIcon={<FiligranIcon icon={LogoXtmOneIcon} size="small" />}
          endIcon={isEnterpriseEdition
            ? undefined
            : <EEChip clickable={false} style={{ marginInlineStart: 0 }} />}
        >
          {t_i18n('Ask Ariane')}
        </Button>
      </EETooltip>

      {/* V3 XTM One panel (xtm_one_token configured) */}
      {isChatbotEnabled && isOpen && !useLegacy && xtmOneConfigured === true && (
        <AskArianePanel
          mode={mode}
          onClose={closeChat}
          onModeChange={setMode}
          onWidthChange={setSidebarWidth}
          onResizeStart={() => setIsResizing(true)}
          onResizeEnd={() => setIsResizing(false)}
        />
      )}

      {openValidateTermsOfUse && (
        <ValidateTermsOfUseDialog open={openValidateTermsOfUse} onClose={() => setOpenValidateTermsOfUse(false)} />
      )}
    </>
  );
};

AskArianeButton.displayName = 'AskArianeButton';

export default AskArianeButton;
