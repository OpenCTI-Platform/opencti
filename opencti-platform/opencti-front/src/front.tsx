import React, { Suspense } from 'react';
import { createRoot } from 'react-dom/client';
import '@filigran/design-system/dist/index.css';
import './static/css/index.css';
import './static/css/custom-theme-tokens.css';
import './static/css/design-system-host.css';
import { styled } from '@mui/material/styles';
import { RelayEnvironmentProvider } from 'react-relay';
import App from './app';
import { environment } from './relay/environment';
import Loader from './components/Loader';
import { THEME_DARK_DEFAULT_BACKGROUND } from './components/ThemeDark';

const LoadingContainer = styled('div')({
  width: '100%',
  height: '100%',
  backgroundColor: THEME_DARK_DEFAULT_BACKGROUND,
});

const Loading = () => {
  return (
    <LoadingContainer>
      <Loader />
    </LoadingContainer>
  );
};

const container = document.getElementById('root');

const root = createRoot(container!);

root.render(
  <RelayEnvironmentProvider environment={environment}>
    <Suspense fallback={<Loading />}>
      <App />
    </Suspense>
  </RelayEnvironmentProvider>,
);
