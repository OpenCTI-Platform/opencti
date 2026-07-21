import React from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Navigate, useLocation, useParams } from 'react-router-dom';
import { NoMatch } from '@components/Error';
import { BYPASS, SETTINGS_SETMANAGEXTMHUB, getCapabilitiesName } from '../../utils/hooks/useGranted';
import type { RedirectByPathQuery as RedirectByPathQueryType } from './__generated__/RedirectByPathQuery.graphql';

export const XTM_HUB_AUTO_REGISTER_QUERY_PARAM = 'xtmHubAutoRegister';
export const XTM_HUB_PERMISSION_REQUIRED_QUERY_PARAM = 'xtmHubPermissionRequired';

const redirectByPathQuery = graphql`
  query RedirectByPathQuery {
    me {
      capabilities {
        name
      }
    }
  }
`;

const STATIC_PATH_REDIRECTS: Record<string, string> = {
  'connect-xtm-hub': '/dashboard/settings/experience',
};

const PATH_REDIRECT_QUERY_PARAMS: Record<string, Record<string, string>> = {
  'connect-xtm-hub': {
    [XTM_HUB_AUTO_REGISTER_QUERY_PARAM]: 'true',
  },
};

const normalizePathKey = (value?: string) => (value ?? '').replace(/^\/+|\/+$/g, '');

const RedirectByPath = () => {
  const { '*': pathKey } = useParams();
  const { search } = useLocation();
  const data = useLazyLoadQuery<RedirectByPathQueryType>(redirectByPathQuery, {});
  const userCapabilities = getCapabilitiesName(data.me.capabilities);
  const isGrantedToXtmHubRegistration = userCapabilities.includes(BYPASS)
    || userCapabilities.some((cap) => cap !== BYPASS && cap.includes(SETTINGS_SETMANAGEXTMHUB));
  const normalizedPathKey = normalizePathKey(pathKey);
  const targetPath = STATIC_PATH_REDIRECTS[normalizedPathKey];

  if (!targetPath) {
    return <NoMatch />;
  }

  const searchParams = new URLSearchParams(search);
  if (normalizedPathKey === 'connect-xtm-hub' && !isGrantedToXtmHubRegistration) {
    searchParams.set(XTM_HUB_PERMISSION_REQUIRED_QUERY_PARAM, 'true');
    const targetSearch = searchParams.toString();
    return <Navigate to={{ pathname: '/dashboard', search: targetSearch ? `?${targetSearch}` : '' }} replace={true} />;
  }

  const extraParams = PATH_REDIRECT_QUERY_PARAMS[normalizedPathKey] ?? {};
  Object.entries(extraParams).forEach(([key, value]) => searchParams.set(key, value));
  const targetSearch = searchParams.toString();

  return <Navigate to={{ pathname: targetPath, search: targetSearch ? `?${targetSearch}` : '' }} replace={true} />;
};

export default RedirectByPath;
