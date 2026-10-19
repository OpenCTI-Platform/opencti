import { useEffect, useRef, useCallback, useState } from 'react';

interface UseExternalTabProps {
  url: string;
  tabName: string;
  expectedOrigin: string | null;
  onMessage: (event: MessageEvent) => void;
  onClosingTab: () => void;
}

const CLOSING_TAB_ACTIONS = ['cancel', 'register', 'unregister'];

interface UseExternalTabReturn {
  isTabOpen: boolean;
  openTab: () => void;
  closeTab: () => void;
  focusTab: () => void;
}

const useExternalTab = ({
  url,
  tabName,
  expectedOrigin,
  onMessage,
  onClosingTab,
}: UseExternalTabProps): UseExternalTabReturn => {
  const tabRef = useRef<WindowProxy | null>(null);
  const [isTabOpen, setIsTabOpen] = useState(false);
  const beforeUnloadHandler = (event: BeforeUnloadEvent) => {
    event.preventDefault();
    return null;
  };

  const openTab = useCallback(() => {
    setIsTabOpen(true);
    tabRef.current = window.open(url, tabName);
  }, [url, tabName]);

  const closeTab = useCallback(() => {
    tabRef.current?.close();
    tabRef.current = null;
    setIsTabOpen(false);
  }, []);

  const focusTab = useCallback(() => {
    tabRef.current?.focus();
  }, []);

  useEffect(() => {
    const handleMessage = (event: MessageEvent) => {
      if (event.source !== tabRef.current) {
        return;
      }
      const isClosingTabAction = CLOSING_TAB_ACTIONS.includes(event.data?.action);
      if (event.origin !== expectedOrigin) {
        if (isClosingTabAction) {
          console.warn(`XTM Hub: message ignored, it comes from "${event.origin}" but the configured XTM Hub origin is "${expectedOrigin}"`);
        }
        return;
      }
      if (isClosingTabAction) {
        closeTab();
      }
      onMessage(event);
    };
    if (isTabOpen) {
      window.addEventListener('message', handleMessage);
      window.addEventListener('beforeunload', beforeUnloadHandler);
      const checkInterval = setInterval(() => {
        if (tabRef.current?.closed) {
          onClosingTab();
          closeTab();
          clearInterval(checkInterval);
        }
      }, 500);
    }

    return () => {
      window.removeEventListener('message', handleMessage);
      window.removeEventListener('beforeunload', beforeUnloadHandler);
    };
  }, [isTabOpen, expectedOrigin]);

  return {
    isTabOpen,
    openTab,
    closeTab,
    focusTab,
  };
};

export default useExternalTab;
