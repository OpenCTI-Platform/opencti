import 'typeface-ibm-plex-sans';
import 'typeface-roboto';
import React from 'react';
import ReactDOM from 'react-dom';
import { RelayEnvironmentProvider } from 'react-relay/hooks';
import './static/css/index.css';
import './static/css/leaflet.css';
import './static/css/CKEditorDark.css';
import './static/css/CKEditorLight.css';
import 'react-grid-layout/css/styles.css';
import 'react-mde/lib/styles/css/react-mde-all.css';
import * as serviceWorker from './config/serviceWorker';
import App from './app';
import { environment } from './relay/environment';
import Loader from './components/Loader';
import ThemeDark from './components/ThemeDark';

const { Suspense } = React;

const Loading = () => (
  <div
    style={{
      width: '100%',
      height: '100%',
      backgroundColor: ThemeDark().palette.background.default,
    }}>
    <Loader variant={'container'} withRightPadding={false} />
  </div>
);

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
