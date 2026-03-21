import React, { createContext, useContext, useState, useCallback, useMemo, ReactNode } from 'react';
import type { ChatMode } from '@filigran/chatbot';

interface ChatbotContextType {
  isOpen: boolean;
  mode: ChatMode;
  sidebarWidth: number;
  isResizing: boolean;
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
const DEFAULT_SIDEBAR_WIDTH = 400;

interface ChatbotProviderProps {
  children: ReactNode;
}

export const ChatbotProvider: React.FC<ChatbotProviderProps> = ({ children }) => {
  const [isOpen, setIsOpen] = useState(false);
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

  const openChat = useCallback(() => setIsOpen(true), []);
  const closeChat = useCallback(() => setIsOpen(false), []);
  const toggleChat = useCallback(() => setIsOpen((prev) => !prev), []);

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
    openChat,
    closeChat,
    toggleChat,
    setMode,
    setSidebarWidth,
    setIsResizing,
  }), [isOpen, mode, sidebarWidth, isResizing, openChat, closeChat, toggleChat, setMode, setSidebarWidth]);

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

// Hook to get the margin right for content when sidebar is open
export const useChatbotContentMargin = (): number => {
  const context = useContext(ChatbotContext);
  if (!context) return 0;

  const { isOpen, mode, sidebarWidth } = context;
  if (isOpen && mode === 'sidebar') {
    return sidebarWidth;
  }
  return 0;
};

// Hook to get transition style for content
export const useChatbotContentTransition = (theme: { transitions: { create: (props: string | string[], options?: { easing?: string; duration?: number }) => string; easing: { easeInOut: string }; duration: { enteringScreen: number } } }): string => {
  const context = useContext(ChatbotContext);
  if (!context) return 'none';

  const { isResizing } = context;
  if (isResizing) return 'none';

  return theme.transitions.create(['margin-right'], {
    easing: theme.transitions.easing.easeInOut,
    duration: theme.transitions.duration.enteringScreen,
  });
};
