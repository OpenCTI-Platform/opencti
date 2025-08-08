import { useEffect, useRef, useCallback, useState } from 'react';

interface UseExternalTabProps {
  url: string;
  tabName: string;
  onMessage: (event: MessageEvent) => void;
  onClosingTab: () => void;
}

interface UseExternalTabReturn {
  isTabOpen: boolean;
  openTab: () => void;
  closeTab: () => void;
  focusTab: () => void;
}

const useExternalTab = ({
  url,
  tabName,
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
      if (event.source === tabRef.current) {
        const closingTabEvent = ['cancel', 'register', 'unregister'];
        if (closingTabEvent.includes(event.data.action)) {
          closeTab();
        }
        onMessage(event);
      }
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
  }, [isTabOpen]);

  return {
    isTabOpen,
    openTab,
    closeTab,
    focusTab,
  };
};

export default useExternalTab;
