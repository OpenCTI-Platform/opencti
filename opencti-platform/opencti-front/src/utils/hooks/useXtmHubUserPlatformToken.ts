import { useEffect, useState } from 'react';
import { getSessionStorageItem, setSessionStorageItem } from '../sessionStorage';

const XTM_HUB_USER_PLATFORM_TOKEN_KEY = 'XTM_HUB_USER_PLATFORM_TOKEN_KEY';

interface Return {
  userPlatformToken: string | null
}

const useXtmHubUserPlatformToken = (): Return => {
  const [token, setToken] = useState<string | null>(null);
  const onMessage = (event: MessageEvent) => {
    const { action, token: newToken } = event.data;
    if (action === 'set-token') {
      setToken(newToken);
      setSessionStorageItem<string>(XTM_HUB_USER_PLATFORM_TOKEN_KEY, newToken);
    }
  };

  useEffect(() => {
    const handleMessage = (event: MessageEvent) => {
      if (event.source === window.opener && onMessage) {
        onMessage(event);
      }
    };
    window.addEventListener('message', handleMessage);

    return () => {
      window.removeEventListener('message', handleMessage);
    };
  }, []);

  useEffect(() => {
    if (token) {
      return;
    }

    const tokenFromStorage = getSessionStorageItem<string>(XTM_HUB_USER_PLATFORM_TOKEN_KEY);
    if (tokenFromStorage) {
      setToken(tokenFromStorage);
    } else {
      window.opener?.postMessage({ action: 'refresh-token' }, '*');
    }
  }, [token]);

  return {
    userPlatformToken: token,
  };
};

export default useXtmHubUserPlatformToken;
