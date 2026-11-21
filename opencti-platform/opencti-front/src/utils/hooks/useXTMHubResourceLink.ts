import { useContext, useMemo } from 'react';
import { UserContext } from './useAuth';
import { isRelativeUrl } from '../url';

export const useXTMHubResourceLink = (urlPath?: string | null) => {
  const { settings } = useContext(UserContext);
  return useMemo(() => {
    if (!settings?.platform_xtmhub_url || !urlPath || !isRelativeUrl(urlPath)) {
      return undefined;
    }

    let url: URL | undefined;
    let hubOrigin: string;
    try {
      hubOrigin = new URL(settings.platform_xtmhub_url).origin;
      url = new URL(urlPath, settings.platform_xtmhub_url);
    } catch (_) {
      // catch malformed URL
      return undefined;
    }

    // URL parsing normalizes some paths (e.g. `/\evil.example`) into another host:
    // whatever the path looks like, the link must stay on the Hub.
    if (url.origin !== hubOrigin) {
      return undefined;
    }

    url.searchParams.append('platform_id', settings.id);

    return url.toString();
  }, [settings, urlPath]);
};
