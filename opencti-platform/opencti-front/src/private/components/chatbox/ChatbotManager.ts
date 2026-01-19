import type { Theme } from '../../../components/Theme';
import { APP_BASE_PATH, fileUri } from '../../../relay/environment';
import embleme from '../../../static/images/embleme_filigran_white.png';
import { DARK_BLUE } from '../../../utils/htmlToPdf/utils/constants';
import { BubbleProps } from '@filigran/chatbot';

type FiligranChatbotElement = HTMLElement & BubbleProps;

/**
 * ChatbotManager is necessary to be sure one instance only runs when we initialized it
 * It creates the web component filigran-chatbot and appends it to the body
 */
class ChatbotManager {
  private static instance: ChatbotManager;
  private chatbotElement: FiligranChatbotElement | null = null;
  private container: HTMLDivElement | null = null;
  private isInitialized = false;
  private theme: Theme | null = null;
  private t_i18n: ((message: string) => string) | null = null;
  private bannerHeight: number = 0;

  static getInstance(): ChatbotManager {
    if (!ChatbotManager.instance) {
      ChatbotManager.instance = new ChatbotManager();
    }
    return ChatbotManager.instance;
  }

  configure(theme: Theme, t_i18n: (message: string) => string, bannerHeight: number = 0) {
    this.theme = theme;
    this.t_i18n = t_i18n;
    this.bannerHeight = bannerHeight;

    if (this.isInitialized) {
      this.updateCustomCSS();
    }
  }

  private getCustomCSS(): string {
    const totalOffset = 68 + this.bannerHeight;
    return `
      * {
        font-family: "IBM Plex Sans" !important;
      }
      div[part="bot"] {
        height: calc(100% - ${totalOffset}px) !important;
        max-height: inherit !important;
        bottom: 0 !important;
        left: unset !important;
        right: 0 !important;
      }
      div[part="bot"] > div > div > div {
        border-radius: 0 !important;
      }
      div[part="bot"] > div > div > div > div,
      div[part="bot"] > div > div > div > div > div {
        border: 0 !important;
      }
      div[part="bot"] > div > div > div > figure {
        width: 24px !important;
        height: 24px !important;
      }
      div[part="bot"] > div > div > div:first-child > div:first-child {
        width: 5px !important;
      }
    `;
  }

  private updateCustomCSS() {
    if (!this.chatbotElement || !this.theme) return;

    const chatBotTheme = {
      ...this.chatbotElement.theme,
      customCSS: this.getCustomCSS(),
    };

    this.chatbotElement.theme = chatBotTheme;
  }

  private initialize() {
    if (this.isInitialized && this.chatbotElement) {
      return;
    }

    if (!this.theme || !this.t_i18n) {
      return;
    }

    if (!this.container) {
      this.container = document.createElement('div');
      this.container.id = 'chatbot-container';
      document.body.appendChild(this.container);
    }

    const chatbot = document.createElement('filigran-chatbot') as FiligranChatbotElement;
    chatbot.setAttribute('agentic-url', `${APP_BASE_PATH}/chatbot`);

    const chatBotTheme = {
      button: {
        backgroundColor: DARK_BLUE,
      },
      tooltip: {
        showTooltip: false,
      },
      customCSS: this.getCustomCSS(),
      chatWindow: {
        showTitle: true,
        showAgentMessages: false,
        title: this.t_i18n('Ask Ariane'),
        titleAvatarSrc: fileUri(embleme),
        titleBackgroundColor: 'linear-gradient(90deg, #3C108C 0%, #5E1AD5 100%)',
        welcomeMessage: this.t_i18n('Hi there 👋 You\'re speaking with an AI Agent. I\'m here to answer your questions, so what brings you here today?'),
        errorMessage: this.t_i18n('Sorry, an error has occurred, please try again later.'),
        backgroundColor: this.theme.palette.ai.background,
        fontSize: 14,
        starterPromptFontSize: 13,
        clearChatOnReload: false,
        sourceDocsTitle: this.t_i18n('Sources:'),
        renderHTML: true,
        botMessage: {
          backgroundColor: this.theme.palette.background.secondary,
          textColor: this.theme.palette.text?.primary,
        },
        userMessage: {
          backgroundColor: this.theme.palette.ai.dark,
          textColor: this.theme.palette.common?.white,
          showAvatar: false,
        },
        textInput: {
          placeholder: this.t_i18n('Ask a question...'),
          backgroundColor: this.theme.palette.background.secondary,
          textColor: this.theme.palette.text?.primary,
          sendButtonColor: this.theme.palette.ai.main,
          maxChars: 256,
          maxCharsWarningMessage: this.t_i18n('You exceeded the characters limit. Please input less than 256 characters.'),
          autoFocus: true,
          sendMessageSound: false,
          receiveMessageSound: false,
        },
        dateTimeToggle: {
          date: true,
          time: true,
        },
        footer: {
          textColor: this.theme.palette.text?.primary,
          text: this.t_i18n('Powered by'),
          company: 'Filigran XTM One',
          companyLink: 'https://filigran.io',
        },
      },
    };

    chatbot.theme = chatBotTheme;
    chatbot.open = false;

    this.container.appendChild(chatbot);
    this.chatbotElement = chatbot;
    this.isInitialized = true;
  }

  open() {
    if (!this.isInitialized) {
      this.initialize();
    }

    if (!this.chatbotElement) return;
    this.chatbotElement.open = true;
  }

  close() {
    if (!this.chatbotElement) return;
    this.chatbotElement.open = false;
  }

  setOnClose(callback: () => void) {
    if (!this.chatbotElement) return;
    this.chatbotElement.onClose = callback;
  }

  destroy() {
    if (this.container) {
      this.container.remove();
      this.container = null;
    }
    this.chatbotElement = null;
    this.isInitialized = false;
    this.theme = null;
    this.t_i18n = null;
  }

  isReady(): boolean {
    return this.isInitialized;
  }
}

export default ChatbotManager;
