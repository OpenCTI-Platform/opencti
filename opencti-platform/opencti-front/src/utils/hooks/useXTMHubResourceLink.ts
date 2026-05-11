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
    try {
      url = new URL(urlPath, settings.platform_xtmhub_url);
    } catch (_) {
      // catch malformed URL
      return undefined;
    }

    url.searchParams.append('platform_id', settings.id);

    return url.toString();
  }, [settings, urlPath]);
};
