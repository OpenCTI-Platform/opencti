import React from 'react';
import { Navigate, useLocation, useParams } from 'react-router-dom';
import { NoMatch } from '@components/Error';

const STATIC_PATH_REDIRECTS: Record<string, string> = {
  'connect-xtm-hub': '/dashboard/settings/experience',
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

  return <Navigate to={{ pathname: targetPath, search }} replace={true} />;
};

export default RedirectByPath;
