import { useEffect, useState } from 'react';
import { getSessionStorageItem, setSessionStorageItem } from '../sessionStorage';
import { getXtmHubOrigin } from '../xtm-hub-client';

const XTM_HUB_USER_PLATFORM_TOKEN_KEY = 'XTM_HUB_USER_PLATFORM_TOKEN_KEY';

interface Return {
  userPlatformToken: string | null;
}

const useXtmHubUserPlatformToken = (hubUrl?: string | null): Return => {
  const [token, setToken] = useState<string | null>(null);
  const hubOrigin = getXtmHubOrigin(hubUrl);
  const onMessage = (event: MessageEvent) => {
    const { action, token: newToken } = event.data;
    if (action === 'set-token') {
      setToken(newToken);
      setSessionStorageItem<string>(XTM_HUB_USER_PLATFORM_TOKEN_KEY, newToken);
    }
  };

  useEffect(() => {
    const handleMessage = (event: MessageEvent) => {
      if (event.source !== window.opener) {
        return;
      }
      if (event.origin !== hubOrigin) {
        if (event.data?.action === 'set-token') {
          console.warn(`XTM Hub: token ignored, it comes from "${event.origin}" but the configured XTM Hub origin is "${hubOrigin}"`);
        }
        return;
      }
      onMessage(event);
    };
    window.addEventListener('message', handleMessage);

    return () => {
      window.removeEventListener('message', handleMessage);
    };
  }, [hubOrigin]);

  useEffect(() => {
    if (token) {
      return;
    }

    const tokenFromStorage = getSessionStorageItem<string>(XTM_HUB_USER_PLATFORM_TOKEN_KEY);
    if (tokenFromStorage) {
      setToken(tokenFromStorage);
    } else if (hubOrigin) {
      window.opener?.postMessage({ action: 'refresh-token' }, hubOrigin);
    }
  }, [token, hubOrigin]);

  return {
    userPlatformToken: token,
  };
};

export default useXtmHubUserPlatformToken;
