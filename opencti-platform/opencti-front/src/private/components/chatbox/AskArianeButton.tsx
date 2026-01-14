import Button from '@common/button/Button';
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
import ChatbotManager from './ChatbotManager';

const AskArianeButton = () => {
  const { t_i18n } = useFormatter();
  const { isChatbotAiEnabled } = useHelper();
  const { settings: { filigran_chatbot_ai_cgu_status } } = useAuth();
  const theme = useTheme<Theme>();
  const isEnterpriseEdition = useEnterpriseEdition();
  const hasRightToValidateCGU = useGranted([SETTINGS_SETPARAMETERS]);

  const isCGUStatusPending = filigran_chatbot_ai_cgu_status === CGUStatus.pending;
  const [isChatbotOpen, setIsChatbotOpen] = useState(false);
  const [openValidateTermsOfUse, setOpenValidateTermsOfUse] = useState(false);

  const chatbotManager = useRef(ChatbotManager.getInstance());
  const isChatbotEnabled = isEnterpriseEdition && isChatbotAiEnabled();

  useEffect(() => {
    if (isChatbotEnabled) {
      chatbotManager.current.configure(theme, t_i18n);
    }
  }, [isChatbotEnabled, theme, t_i18n]);

  useEffect(() => {
    if (!isChatbotEnabled && chatbotManager.current.isReady()) {
      chatbotManager.current.destroy();
    }
  }, [isChatbotEnabled]);

  const openChatbot = () => {
    setIsChatbotOpen(true);
    chatbotManager.current.open();
  };

  const closeChatbot = () => {
    setIsChatbotOpen(false);
    chatbotManager.current.close();
  };

  useEffect(() => {
    if (chatbotManager.current.isReady()) {
      chatbotManager.current.setOnClose(closeChatbot);
    }
  }, [chatbotManager.current.isReady()]);

  const toggleChatbot = () => {
    if (filigran_chatbot_ai_cgu_status === CGUStatus.enabled) {
      if (isChatbotOpen) {
        closeChatbot();
      } else {
        openChatbot();
      }
    } else if (hasRightToValidateCGU) {
      setOpenValidateTermsOfUse(true);
    }
  };

  return (
    <>
      <EETooltip
        title={isCGUStatusPending && !hasRightToValidateCGU ? t_i18n('Ask Ariane isn\'t activated yet. Please reach out to your administrator to enable this feature.') : 'Open chatbot'}
      >
        <Button
          variant="tertiary"
          gradient
          gradientVariant="ai"
          onClick={toggleChatbot}
          startIcon={<FiligranIcon icon={LogoXtmOneIcon} size="small" color="ai" />}
        >
          {t_i18n('Ask Ariane')}
          <EEChip />
        </Button>
      </EETooltip>

      {openValidateTermsOfUse && (
        <ValidateTermsOfUseDialog open={openValidateTermsOfUse} onClose={() => setOpenValidateTermsOfUse(false)} />
      )}
    </>
  );
};

AskArianeButton.displayName = 'AskArianeButton';

export default AskArianeButton;
