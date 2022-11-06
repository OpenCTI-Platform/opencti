import 'typeface-ibm-plex-sans';
import 'typeface-roboto';
import { Suspense } from 'react';
import ReactDOM from 'react-dom';
import makeStyles from '@mui/styles/makeStyles';
import { RelayEnvironmentProvider } from 'react-relay/hooks';
import './static/css/index.css';
import './static/css/leaflet.css';
import './static/css/CKEditorDark.css';
import './static/css/CKEditorLight.css';
import 'react-grid-layout/css/styles.css';
import 'react-mde/lib/styles/css/react-mde-all.css';
import 'flag-icons/css/flag-icons.min.css';
import * as serviceWorker from './config/serviceWorker';
import App from './app';
import { environment } from './relay/environment';
import Loader, { LoaderVariant } from './components/Loader';
import { THEME_DARK_DEFAULT_BACKGROUND } from './components/ThemeDark';

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
      <Loader variant={LoaderVariant.container} withRightPadding={false} />
    </div>
  );
};

ReactDOM.render(
  <RelayEnvironmentProvider environment={environment}>
    <Suspense fallback={<Loading />}>
      <App />
    </Suspense>
  </RelayEnvironmentProvider>,
  document.getElementById('root'),
);

// If you want your app to work offline and load faster, you can change
// unregister() to register() below. Note this comes with some pitfalls.
// Learn more about service workers: http://bit.ly/CRA-PWA
serviceWorker.unregister();
