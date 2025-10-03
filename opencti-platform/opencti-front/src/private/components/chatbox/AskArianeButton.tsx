import EEChip from '@components/common/entreprise_edition/EEChip';
import React, { useEffect, useImperativeHandle, useRef, useState } from 'react';
import { OPEN_BAR_WIDTH, SMALL_BAR_WIDTH } from '@components/nav/LeftBar';
import { useTheme } from '@mui/styles';
import { CGUStatus } from '@components/settings/Experience';
import ValidateTermsOfUseDialog from '@components/settings/ValidateTermsOfUseDialog';
import { LogoXtmOneIcon } from 'filigran-icon';
import FiligranIcon from '@components/common/FiligranIcon';
import EETooltip from '@components/common/entreprise_edition/EETooltip';
import GradientButton, { GradientVariant } from '../../../components/GradientButton';
import { useFormatter } from '../../../components/i18n';
import useEnterpriseEdition from '../../../utils/hooks/useEnterpriseEdition';
import type { Theme } from '../../../components/Theme';
import { APP_BASE_PATH, fileUri, MESSAGING$ } from '../../../relay/environment';
import { DARK_BLUE } from '../../../utils/htmlToPdf/utils/constants';
import embleme from '../../../static/images/embleme_filigran_white.png';
import useHelper from '../../../utils/hooks/useHelper';
import useAuth from '../../../utils/hooks/useAuth';
import useGranted, { SETTINGS_SETPARAMETERS } from '../../../utils/hooks/useGranted';

const AskArianeButton = React.forwardRef((props, ref) => {
  const { t_i18n } = useFormatter();
  const { isChatbotAiEnabled } = useHelper();
  const { settings: { filigran_chatbot_ai_cgu_status } } = useAuth();
  const theme = useTheme<Theme>();
  const isEnterpriseEdition = useEnterpriseEdition();
  const hasRightToValidateCGU = useGranted([SETTINGS_SETPARAMETERS]);

  const [navOpen, setNavOpen] = useState(
    localStorage.getItem('navOpen') === 'true',
  );
  useEffect(() => {
    const sub = MESSAGING$.toggleNav.subscribe({
      next: () => setNavOpen(localStorage.getItem('navOpen') === 'true'),
    });
    return () => {
      sub.unsubscribe();
    };
  });

  const isCGUStatusPending = filigran_chatbot_ai_cgu_status === CGUStatus.pending;
  const [isChatbotOpen, setIsChatbotOpen] = useState(false);
  const [openValidateTermsOfUse, setOpenValidateTermsOfUse] = useState(false);
  const chatbotRef = useRef<{ onClose:() => void }>(null);

  const openChatbot = () => {
    setIsChatbotOpen(true);
  };

  const closeChatbot = () => {
    setIsChatbotOpen(false);
  };

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

  useImperativeHandle(ref, () => ({
    toggleChatbot,
  }));

  // Handle the close event from the chatbot component
  useEffect(() => {
    if (chatbotRef.current) {
      chatbotRef.current.onClose = closeChatbot;
    }
  }, [isChatbotOpen]);

  const chatBotTheme = {
    button: {
      backgroundColor: DARK_BLUE,
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
      title: t_i18n('[Preview] Ask Ariane'),
      titleAvatarSrc: fileUri(embleme),
      titleBackgroundColor: theme.palette.ai.dark,
      welcomeMessage: t_i18n('Hi there 👋 You\'re speaking with an AI Agent. I\'m here to answer your questions, so what brings you here today?'),
      errorMessage: t_i18n('Sorry, an error has occurred, please try again later.'),
      backgroundColor: theme.palette.background.paper,
      fontSize: 14,
      starterPromptFontSize: 13,
      clearChatOnReload: false,
      sourceDocsTitle: t_i18n('Sources:'),
      renderHTML: true,
      boxShadow: `${theme.palette.background.shadow} 0px 5px 40px`,
      botMessage: {
        backgroundColor: theme.palette.background.accent,
        textColor: theme.palette.text?.primary,
      },
      userMessage: {
        backgroundColor: theme.palette.ai.dark,
        textColor: theme.palette.common?.white,
        showAvatar: false,
      },
      textInput: {
        placeholder: t_i18n('Ask a question...'),
        backgroundColor: theme.palette.background.paper,
        textColor: theme.palette.text?.primary,
        sendButtonColor: theme.palette.ai.main,
        maxChars: 256,
        maxCharsWarningMessage: t_i18n('You exceeded the characters limit. Please input less than 256 characters.'),
        autoFocus: true,
        sendMessageSound: false,
        receiveMessageSound: false,
      },
      dateTimeToggle: {
        date: true,
        time: true,
      },
      footer: {
        textColor: theme.palette.text?.disabled,
        text: t_i18n('Powered by'),
        company: 'Filigran XTM One',
        companyLink: 'https://filigran.io',
      },
    },
  };
  const chatbotProxyUrl = `${APP_BASE_PATH}/chatbot`;

  const chatIconStyle: React.CSSProperties = {
    color: isCGUStatusPending ? theme.palette.action?.disabled : undefined,
  };

  return (
    <>
      <EETooltip
        title={isCGUStatusPending && !hasRightToValidateCGU ? t_i18n('Ask Ariane isn\'t activated yet. Please reach out to your administrator to enable this feature.') : 'Open chatbot'}
      >
        {navOpen ? (
          <GradientButton
            size="small"
            sx={{ width: '100%', paddingLeft: '8px' }}
            gradientVariant={isCGUStatusPending ? GradientVariant.disabled : GradientVariant.ai}
            onClick={toggleChatbot}
            startIcon={ <FiligranIcon icon={LogoXtmOneIcon} size='small' color="ai" style={chatIconStyle} />}
          >
            {t_i18n('ASK ARIANE')}
            <EEChip />
          </GradientButton>
        ) : (
          <GradientButton
            size="small"
            sx={{ margin: '-4px', marginLeft: '-6px', marginTop: '-4px', minWidth: 'auto', paddingLeft: 1, paddingY: theme.spacing(0.5) }}
            gradientVariant={isCGUStatusPending ? GradientVariant.disabled : GradientVariant.ai}
            onClick={toggleChatbot}
            startIcon={ <FiligranIcon icon={LogoXtmOneIcon} size='small' color="ai" style={chatIconStyle} />}
          >
          </GradientButton>
        )}
      </EETooltip>
      {isEnterpriseEdition && isChatbotAiEnabled() ? (
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
        <filigran-chatbot
          ref={chatbotRef}
          open={isChatbotOpen}
          left={navOpen ? OPEN_BAR_WIDTH : SMALL_BAR_WIDTH}
          agentic-url={chatbotProxyUrl}
          theme={JSON.stringify(chatBotTheme)}
        />
      ) : null}

      {openValidateTermsOfUse && (
        <ValidateTermsOfUseDialog open={openValidateTermsOfUse} onClose={() => setOpenValidateTermsOfUse(false)}/>
      )}
    </>
  );
});

AskArianeButton.displayName = 'AskArianeButton';

export default AskArianeButton;
