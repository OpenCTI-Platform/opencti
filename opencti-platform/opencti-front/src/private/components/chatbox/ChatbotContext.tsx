import React, { createContext, useContext, useState, useCallback, useMemo, useEffect, ReactNode } from 'react';
import type { ChatMode } from '@filigran/chatbot';
import { APP_BASE_PATH } from '../../../relay/environment';

interface ChatbotContextType {
  isOpen: boolean;
  mode: ChatMode;
  sidebarWidth: number;
  isResizing: boolean;
  xtmOneConfigured: boolean | null;
  xtmOneUrl: string | null;
  openChat: () => void;
  closeChat: () => void;
  toggleChat: () => void;
  setMode: (mode: ChatMode) => void;
  setSidebarWidth: (width: number) => void;
  setIsResizing: (isResizing: boolean) => void;
}

const ChatbotContext = createContext<ChatbotContextType | null>(null);

const SIDEBAR_WIDTH_STORAGE_KEY = 'arianeChatSidebarWidth';
const CHAT_MODE_STORAGE_KEY = 'arianeChatMode';
const CHAT_OPEN_STORAGE_KEY = 'arianeChatOpen';
const DEFAULT_SIDEBAR_WIDTH = 400;

interface ChatbotProviderProps {
  children: ReactNode;
}

export const ChatbotProvider: React.FC<ChatbotProviderProps> = ({ children }) => {
  const [isOpen, setIsOpen] = useState(() => localStorage.getItem(CHAT_OPEN_STORAGE_KEY) === 'true');
  const [xtmOneConfigured, setXtmOneConfigured] = useState<boolean | null>(null);
  const [xtmOneUrl, setXtmOneUrl] = useState<string | null>(null);
  const [mode, setModeState] = useState<ChatMode>(() => {
    const stored = localStorage.getItem(CHAT_MODE_STORAGE_KEY);
    return (stored as ChatMode) || 'sidebar';
  });
  const [sidebarWidth, setSidebarWidthState] = useState(() => {
    const stored = localStorage.getItem(SIDEBAR_WIDTH_STORAGE_KEY);
    if (stored) {
      const parsed = parseInt(stored, 10);
      if (!Number.isNaN(parsed) && parsed >= 300) return parsed;
    }
    return DEFAULT_SIDEBAR_WIDTH;
  });
  const [isResizing, setIsResizing] = useState(false);

  useEffect(() => {
    fetch(`${APP_BASE_PATH}/chatbot/config`)
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        setXtmOneConfigured(data?.xtm_one_configured === true);
        setXtmOneUrl(typeof data?.xtm_one_url === 'string' ? data.xtm_one_url : null);
      })
      .catch(() => {
        setXtmOneConfigured(false);
        setXtmOneUrl(null);
      });
  }, []);

  const openChat = useCallback(() => {
    setIsOpen(true);
    localStorage.setItem(CHAT_OPEN_STORAGE_KEY, 'true');
  }, []);
  const closeChat = useCallback(() => {
    setIsOpen(false);
    localStorage.setItem(CHAT_OPEN_STORAGE_KEY, 'false');
  }, []);
  const toggleChat = useCallback(() => {
    setIsOpen((prev) => {
      const next = !prev;
      localStorage.setItem(CHAT_OPEN_STORAGE_KEY, String(next));
      return next;
    });
  }, []);

  const setMode = useCallback((newMode: ChatMode) => {
    setModeState(newMode);
    localStorage.setItem(CHAT_MODE_STORAGE_KEY, newMode);
  }, []);

  const setSidebarWidth = useCallback((width: number) => {
    setSidebarWidthState(width);
    localStorage.setItem(SIDEBAR_WIDTH_STORAGE_KEY, String(width));
  }, []);

  const value = useMemo(() => ({
    isOpen,
    mode,
    sidebarWidth,
    isResizing,
    xtmOneConfigured,
    xtmOneUrl,
    openChat,
    closeChat,
    toggleChat,
    setMode,
    setSidebarWidth,
    setIsResizing,
  }), [isOpen, mode, sidebarWidth, isResizing, xtmOneConfigured, xtmOneUrl, openChat, closeChat, toggleChat, setMode, setSidebarWidth]);

  return (
    <ChatbotContext.Provider value={value}>
      {children}
    </ChatbotContext.Provider>
  );
};

export const useChatbot = (): ChatbotContextType => {
  const context = useContext(ChatbotContext);
  if (!context) {
    throw new Error('useChatbot must be used within a ChatbotProvider');
  }
  return context;
};
