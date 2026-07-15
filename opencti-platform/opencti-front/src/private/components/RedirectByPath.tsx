import React from 'react';
import { Navigate, useLocation, useParams } from 'react-router-dom';
import { NoMatch } from '@components/Error';

export const XTM_HUB_AUTO_REGISTER_QUERY_PARAM = 'xtmHubAutoRegister';
export const XTM_HUB_PRODUCT_NAME_QUERY_PARAM = 'productName';

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
  const normalizedPathKey = normalizePathKey(pathKey);
  const targetPath = STATIC_PATH_REDIRECTS[normalizedPathKey];

  if (!targetPath) {
    return <NoMatch />;
  }

  const searchParams = new URLSearchParams(search);
  const extraParams = PATH_REDIRECT_QUERY_PARAMS[normalizedPathKey] ?? {};
  Object.entries(extraParams).forEach(([key, value]) => searchParams.set(key, value));
  const targetSearch = searchParams.toString();

  return <Navigate to={{ pathname: targetPath, search: targetSearch ? `?${targetSearch}` : '' }} replace={true} />;
};

export default RedirectByPath;
