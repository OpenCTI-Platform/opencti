import { AutoAwesomeOutlined } from '@mui/icons-material';
import EEChip from '@components/common/entreprise_edition/EEChip';
import React, { useEffect, useRef, useState } from 'react';
import { OPEN_BAR_WIDTH, SMALL_BAR_WIDTH } from '@components/nav/LeftBar';
import { useTheme } from '@mui/styles';
import IconButton from '@mui/material/IconButton';
import GradientButton, { GradientVariant } from '../../../components/GradientButton';
import { useFormatter } from '../../../components/i18n';
import useAuth from '../../../utils/hooks/useAuth';
import useEnterpriseEdition from '../../../utils/hooks/useEnterpriseEdition';
import type { Theme } from '../../../components/Theme';
import { fileUri, MESSAGING$ } from '../../../relay/environment';
import { DARK_BLUE } from '../../../utils/htmlToPdf/utils/constants';
import { toBase64 } from '../../../utils/String';
import embleme from '../../../static/images/embleme_filigran_white.png';
import useHelper from '../../../utils/hooks/useHelper';

const AskArianeButton = () => {
  const { t_i18n } = useFormatter();
  const { isChatbotAiEnabled } = useHelper();
  const theme = useTheme<Theme>();
  const isEnterpriseEdition = useEnterpriseEdition();
  const {
    me: { api_token },
    settings: { platform_url, filigran_chatbot_ai_url, platform_enterprise_edition },
  } = useAuth();

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

  const [isChatbotOpen, setIsChatbotOpen] = useState(false);
  const chatbotRef = useRef<{ onClose:() => void }>(null);
  const EERef = useRef<HTMLDivElement>(null);

  const openChatbot = () => {
    setIsChatbotOpen(true);
  };

  const closeChatbot = () => {
    setIsChatbotOpen(false);
  };

  const toggleChatbot = () => {
    if (isChatbotOpen) {
      closeChatbot();
    } else {
      openChatbot();
    }
  };

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
      title: 'Ask Ariane',
      titleAvatarSrc: fileUri(embleme),
      titleBackgroundColor: theme.palette.ai.dark,
      welcomeMessage: 'Hi there 👋 You\'re speaking with an AI Agent. I\'m here to answer your questions, so what brings you here today?',
      errorMessage: 'Sorry, an error has occurred, please try again later.',
      backgroundColor: theme.palette.background.paper,
      fontSize: 14,
      starterPromptFontSize: 13,
      clearChatOnReload: false,
      sourceDocsTitle: 'Sources:',
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
        placeholder: 'Ask a question...',
        backgroundColor: theme.palette.background.paper,
        textColor: theme.palette.text?.primary,
        sendButtonColor: theme.palette.ai.main,
        maxChars: 256,
        maxCharsWarningMessage: 'You exceeded the characters limit. Please input less than 50 characters.',
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
        text: 'Powered by',
        company: 'Filigran XTM One',
        companyLink: 'https://filigran.io',
      },
    },
  };

  const vars = {
    OPENCTI_URL: platform_url,
    OPENCTI_TOKEN: api_token,
    OPENCTI_CERTIFICATE: toBase64(platform_enterprise_edition.license_raw_pem),
  };

  return (
    <>
      {isEnterpriseEdition && isChatbotAiEnabled() ? (
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
        <filigran-chatbot
          ref={chatbotRef}
          open={isChatbotOpen}
          left={navOpen ? OPEN_BAR_WIDTH : SMALL_BAR_WIDTH}
          agentic-url={filigran_chatbot_ai_url}
          theme={JSON.stringify(chatBotTheme)}
          chatflowConfig={{ vars }}
        />
      ) : null}
      {!isEnterpriseEdition && navOpen ? (
        <>
          Ask Ariane
          <EEChip ref={EERef}/>
        </>
      ) : null}

      {navOpen ? (
        <GradientButton
          size="small"
          sx={{ width: '100%', textAlign: 'start' }}
          gradientVariant={GradientVariant.ai}
          title={t_i18n('Open chatbot')}
          onClick={toggleChatbot}
        >
          <AutoAwesomeOutlined style={{ color: theme.palette.ai.main }}/>
          <span style={{ marginLeft: 5 }}>ASK ARIANE</span>
        </GradientButton>
      ) : (
        <IconButton style={{ padding: 0 }} onClick={toggleChatbot}>
          <AutoAwesomeOutlined style={{ color: theme.palette.ai.main }}/>
        </IconButton>
      )}
    </>
  );
};

export default AskArianeButton;
