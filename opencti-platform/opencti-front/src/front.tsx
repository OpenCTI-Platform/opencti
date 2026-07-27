import React, { Suspense } from 'react';
import { createRoot } from 'react-dom/client';
import './static/css/index.css';
import makeStyles from '@mui/styles/makeStyles';
import { RelayEnvironmentProvider } from 'react-relay';
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

const root = createRoot(container!);

root.render(
  <RelayEnvironmentProvider environment={environment}>
    <Suspense fallback={<Loading />}>
      <App />
    </Suspense>
  </RelayEnvironmentProvider>,
);
