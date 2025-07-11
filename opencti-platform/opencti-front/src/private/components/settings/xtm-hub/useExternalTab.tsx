import { useEffect, useRef, useState, useCallback } from 'react';

interface UseExternalTabProps {
  url: string;
  tabName: string;
  setIsDialogOpen: (isOpen: boolean) => void;
  onMessage?: (event: MessageEvent) => void;
}

interface UseExternalTabReturn {
  isTabOpen: boolean;
  openTab: () => void;
  closeTab: () => void;
  focusTab: () => void;
}

const useExternalTab = ({ url, tabName, onMessage, setIsDialogOpen }: UseExternalTabProps): UseExternalTabReturn => {
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
    setIsDialogOpen(false);
  }, []);

  const focusTab = useCallback(() => {
    tabRef.current?.focus();
  }, []);

  useEffect(() => {
    const handleMessage = (event: MessageEvent) => {
      if (event.source === tabRef.current && onMessage) {
        onMessage(event);
      }
    };
    if (isTabOpen) {
      window.addEventListener('message', handleMessage);
      window.addEventListener('beforeunload', beforeUnloadHandler);
      const checkInterval = setInterval(() => {
        if (tabRef.current?.closed) {
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
