import React, { Suspense } from 'react';
import '@fontsource/ibm-plex-sans';
import '@fontsource/geologica';
import { createRoot } from 'react-dom/client';
import makeStyles from '@mui/styles/makeStyles';
import { RelayEnvironmentProvider } from 'react-relay/hooks';
import './static/css/index.css';
import './static/css/leaflet.css';
import './static/css/CKEditorDark.css';
import './static/css/CKEditorLight.css';
import 'react-grid-layout/css/styles.css';
import 'react-mde/lib/styles/css/react-mde-all.css';
import ToastProvider from '@components/common/toasts/ToastProvider';
import * as serviceWorker from './config/serviceWorker';
import App from './app';
import { environment } from './relay/environment';
import Loader from './components/Loader';
import { THEME_DARK_DEFAULT_BACKGROUND } from './components/ThemeDark';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  loading: {
    width: '100%',
    height: '100%',
    backgroundColor: THEME_DARK_DEFAULT_BACKGROUND,
  },
}));

const Loading = () => {
  const classes = useStyles();
  return (
    <div className={classes.loading}>
      <Loader />
    </div>
  );
};

const container = document.getElementById('root');
// eslint-disable-next-line @typescript-eslint/no-non-null-assertion
const root = createRoot(container!);

root.render(
  <RelayEnvironmentProvider environment={environment}>
    <Suspense fallback={<Loading />}>
      <ToastProvider>
        <App />
      </ToastProvider>
    </Suspense>
  </RelayEnvironmentProvider>,
);

// If you want your app to work offline and load faster, you can change
// unregister() to register() below. Note this comes with some pitfalls.
// Learn more about service workers: http://bit.ly/CRA-PWA
serviceWorker.unregister();
