import { AutoAwesomeOutlined } from '@mui/icons-material';
import EEChip from '@components/common/entreprise_edition/EEChip';
import React, { MouseEventHandler, useCallback, useEffect, useRef, useState } from 'react';
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

const AskArianeButton = () => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const isEnterpriseEdition = useEnterpriseEdition();
  const {
    me: { api_token },
    settings: { platform_url, filigran_agentic_ai_url, platform_enterprise_edition },
  } = useAuth();

  // navopen
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

  const chatboxRef = useRef<HTMLDivElement>(null);
  const EEref = useRef<HTMLDivElement>(null);
  const [opened, setOpened] = useState(false);
  const toggleChatbot = useCallback<MouseEventHandler<HTMLButtonElement>>((e) => {
    setOpened(!opened);
    if (!isEnterpriseEdition || !chatboxRef.current) {
      e.stopPropagation();
      if (!opened) {
        EEref.current?.click();
      }
      return;
    }
    const element = chatboxRef.current.shadowRoot?.querySelector('#bot-button');
    element?.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, composed: true }));
  }, [chatboxRef.current, opened]);

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
        backgroundColor: theme.palette.background.default,
        textColor: theme.palette.text?.primary,
        showAvatar: true,
        avatarSrc: fileUri(embleme),
      },
      userMessage: {
        backgroundColor: DARK_BLUE,
        textColor: theme.palette.common?.white,
        showAvatar: false,
      },
      textInput: {
        placeholder: 'Ask a question...',
        backgroundColor: theme.palette.background.paper,
        textColor: theme.palette.text?.primary,
        sendButtonColor: DARK_BLUE,
        maxChars: 100,
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
        company: 'Filigran Ariane AI',
        companyLink: 'https://filigran.io',
      },
    },
  };

  const vars = {
    OPENCTI_URL: platform_url,
    OPENCTI_TOKEN: api_token,
    OPENCTI_CERTIFICATE: toBase64(platform_enterprise_edition.enterprise_license),
  };

  const chatbot = (
    <>
      <AutoAwesomeOutlined
        style={{ color: theme.palette.ai.main }}
      />
      {isEnterpriseEdition ? (
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
        <flowise-chatbot
          ref={chatboxRef}
          text={!navOpen ? '' : 'ASK ARIANE'}
          left={navOpen ? OPEN_BAR_WIDTH : SMALL_BAR_WIDTH}
          onClick={(e: MouseEvent) => e.stopPropagation()}
          agentic-url={filigran_agentic_ai_url}
          theme={chatBotTheme}
          chatflowConfig={{
            vars,
          }}
        />
      ) : (
        <>
          Ask Ariane
          <EEChip ref={EEref} />
        </>
      )}
    </>
  );

  return navOpen ? (
    <GradientButton
      size="small"
      sx={{ width: '100%' }}
      gradientVariant={GradientVariant.ai}
      title={t_i18n('Import from Hub')}
      onClick={toggleChatbot}
    >
      {chatbot}
    </GradientButton>
  ) : (
    <IconButton
      style={{ padding: 0 }}
      onClick={toggleChatbot}
    >
      {chatbot}
    </IconButton>
  );
};

export default AskArianeButton;
